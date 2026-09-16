//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	captureNetNSName  = "dae-ebpf-inbound"
	captureHostLink   = "dae-ebpf0"
	capturePeerLink   = "dae-ebpf1"
	captureLinkTxQLen = 1000
	captureRouteTable = 2023
	captureTProxyMark = uint32(0x08000000)
)

type captureNetNS struct {
	log              *slog.Logger
	token            string
	mu               sync.Mutex
	closed           bool
	hostNS           netns.NsHandle
	captureNS        netns.NsHandle
	hostLink         netlink.Link
	peerLink         netlink.Link
	createdHostLink  bool
	createdNamespace bool
	hostSysctls      *sysctlManager
}

func newCaptureNetNS(ctx context.Context, log *slog.Logger, owner *ownershipLease) (*captureNetNS, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	token := ""
	if owner != nil {
		token = owner.Token()
	}
	ns := &captureNetNS{log: log, token: token, hostNS: netns.None(), captureNS: netns.None()}
	ns.hostSysctls = newSysctlManager(func(mutations []sysctlMutation) error {
		if owner == nil {
			return nil
		}
		return owner.SetSysctls(mutations)
	})
	if err := ns.setup(ctx, owner); err != nil {
		return ns, err
	}
	return ns, nil
}

func (ns *captureNetNS) setup(ctx context.Context, owner *ownershipLease) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ns.hostNS, err = netns.Get()
	if err != nil {
		return fmt.Errorf("get host network namespace: %w", err)
	}
	defer func() {
		if ns.hostNS.IsOpen() {
			_ = netns.Set(ns.hostNS)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if resources := existingCaptureResourcesWithoutRecord(); len(resources) > 0 {
		return fmt.Errorf("refuse existing unowned capture resources: %s", strings.Join(resources, ", "))
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: captureHostLink, TxQLen: captureLinkTxQLen, Alias: ns.token}, PeerName: capturePeerLink, PeerTxQLen: captureLinkTxQLen}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("create capture veth pair: %w", err)
	}
	ns.createdHostLink = true
	ns.hostLink, err = netlink.LinkByName(captureHostLink)
	if err != nil {
		return fmt.Errorf("lookup host capture link: %w", err)
	}
	if err := netlink.LinkSetAlias(ns.hostLink, ns.token); err != nil {
		return fmt.Errorf("mark host capture link ownership: %w", err)
	}
	peerInHost, err := netlink.LinkByName(capturePeerLink)
	if err != nil {
		return fmt.Errorf("lookup peer capture link: %w", err)
	}
	if err := netlink.LinkSetAlias(peerInHost, ns.token); err != nil {
		return fmt.Errorf("mark peer capture link ownership: %w", err)
	}
	if err := netlink.LinkSetUp(ns.hostLink); err != nil {
		return fmt.Errorf("bring host capture link up: %w", err)
	}
	ns.captureNS, err = netns.NewNamed(captureNetNSName)
	if err != nil {
		return fmt.Errorf("create named capture network namespace: %w", err)
	}
	ns.createdNamespace = true
	if owner != nil {
		if err := owner.SetNamespaceIdentity(ns.captureNS); err != nil {
			return fmt.Errorf("record capture network namespace identity: %w", err)
		}
	}
	if err := netns.Set(ns.hostNS); err != nil {
		return fmt.Errorf("restore host network namespace: %w", err)
	}
	if err := netlink.LinkSetNsFd(peerInHost, int(ns.captureNS)); err != nil {
		return fmt.Errorf("move capture peer into namespace: %w", err)
	}
	if err := ns.setupHostSide(); err != nil {
		return err
	}
	if err := ns.withUnlocked(ns.setupNamespaceSide); err != nil {
		return err
	}
	return nil
}

func (ns *captureNetNS) setupHostSide() error {
	for _, setting := range []struct{ family, key, value string }{{"ipv4", "rp_filter", "0"}, {"ipv4", "arp_filter", "0"}, {"ipv4", "accept_local", "1"}, {"ipv6", "disable_ipv6", "0"}, {"ipv6", "forwarding", "1"}} {
		path, err := interfaceSysctlPath(setting.family, captureHostLink, setting.key)
		if err != nil {
			return err
		}
		if err := ns.hostSysctls.Set(path, setting.value); err != nil {
			if setting.family == "ipv6" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
	}
	address := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("fe80::ecee:eeff:feee:eeee"), Mask: net.CIDRMask(128, 128)}}
	if err := netlink.AddrAdd(ns.hostLink, address); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add host capture IPv6 address: %w", err)
	}
	return nil
}

func (ns *captureNetNS) setupNamespaceSide() error {
	var err error
	ns.peerLink, err = netlink.LinkByName(capturePeerLink)
	if err != nil {
		return fmt.Errorf("lookup capture peer in namespace: %w", err)
	}
	if err := netlink.LinkSetAlias(ns.peerLink, ns.token); err != nil {
		return fmt.Errorf("mark peer capture link ownership: %w", err)
	}
	if err := netlink.LinkSetUp(ns.peerLink); err != nil {
		return fmt.Errorf("bring capture peer up: %w", err)
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("lookup namespace loopback: %w", err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		return fmt.Errorf("bring namespace loopback up: %w", err)
	}
	peerAcceptLocal, _ := interfaceSysctlPath("ipv4", capturePeerLink, "accept_local")
	if err := os.WriteFile(peerAcceptLocal, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable peer accept_local: %w", err)
	}
	_ = os.WriteFile("/proc/sys/net/ipv4/tcp_early_demux", []byte("1"), 0o644)
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_early_demux", []byte("1"), 0o644)
	ipv4, network, err := net.ParseCIDR("169.254.0.11/32")
	if err != nil {
		return err
	}
	network.IP = ipv4
	if err := netlink.AddrAdd(ns.peerLink, &netlink.Addr{IPNet: network}); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add capture peer IPv4 address: %w", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: ns.peerLink.Attrs().Index, Dst: &net.IPNet{IP: net.ParseIP("169.254.0.1"), Mask: net.CIDRMask(32, 32)}, Scope: netlink.SCOPE_LINK}); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add capture peer link route: %w", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: ns.peerLink.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Gw: net.ParseIP("169.254.0.1")}); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add capture peer IPv4 default route: %w", err)
	}
	if err := netlink.NeighSet(&netlink.Neigh{IP: net.ParseIP("169.254.0.1"), HardwareAddr: ns.hostLink.Attrs().HardwareAddr, LinkIndex: ns.peerLink.Attrs().Index, State: netlink.NUD_PERMANENT}); err != nil {
		return fmt.Errorf("add capture peer IPv4 neighbor: %w", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: ns.peerLink.Attrs().Index, Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Gw: net.ParseIP("fe80::ecee:eeff:feee:eeee")}); err == nil || errors.Is(err, unix.EEXIST) {
		if err := netlink.NeighSet(&netlink.Neigh{IP: net.ParseIP("fe80::ecee:eeff:feee:eeee"), HardwareAddr: ns.hostLink.Attrs().HardwareAddr, LinkIndex: ns.peerLink.Attrs().Index, State: netlink.NUD_PERMANENT}); err != nil && ns.log != nil {
			ns.log.Warn("IPv6 capture neighbor unavailable", "error", err)
		}
	} else if ns.log != nil {
		ns.log.Warn("IPv6 capture default route unavailable", "error", err)
	}
	routes := []netlink.Route{{Scope: unix.RT_SCOPE_HOST, LinkIndex: loopback.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Table: captureRouteTable, Type: unix.RTN_LOCAL}, {Scope: unix.RT_SCOPE_HOST, LinkIndex: loopback.Attrs().Index, Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Table: captureRouteTable, Type: unix.RTN_LOCAL}}
	for _, route := range routes {
		route := route
		if err := netlink.RouteAdd(&route); err != nil && !errors.Is(err, unix.EEXIST) {
			if route.Dst.IP.To4() == nil {
				if ns.log != nil {
					ns.log.Warn("IPv6 capture local route unavailable", "error", err)
				}
				continue
			}
			return fmt.Errorf("add capture policy route: %w", err)
		}
	}
	mask := captureTProxyMark
	rules := []netlink.Rule{{SuppressIfgroup: -1, SuppressPrefixlen: -1, Priority: -1, Goto: -1, Flow: -1, Family: unix.AF_INET, Table: captureRouteTable, Mark: captureTProxyMark, Mask: &mask}, {SuppressIfgroup: -1, SuppressPrefixlen: -1, Priority: -1, Goto: -1, Flow: -1, Family: unix.AF_INET6, Table: captureRouteTable, Mark: captureTProxyMark, Mask: &mask}}
	for _, rule := range rules {
		rule := rule
		if err := netlink.RuleAdd(&rule); err != nil && !errors.Is(err, unix.EEXIST) {
			if rule.Family == unix.AF_INET6 {
				if ns.log != nil {
					ns.log.Warn("IPv6 capture policy rule unavailable", "error", err)
				}
				continue
			}
			return fmt.Errorf("add capture policy rule: %w", err)
		}
	}
	return nil
}

func (ns *captureNetNS) With(function func() error) error {
	if ns == nil {
		return errors.New("nil capture network namespace")
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.closed || !ns.hostNS.IsOpen() || !ns.captureNS.IsOpen() {
		return errors.New("capture network namespace is closed")
	}
	return ns.withUnlocked(function)
}
func (ns *captureNetNS) withUnlocked(function func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := netns.Set(ns.captureNS); err != nil {
		return fmt.Errorf("enter capture network namespace: %w", err)
	}
	defer func() {
		if restoreErr := netns.Set(ns.hostNS); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore host network namespace: %w", restoreErr))
		}
	}()
	if function == nil {
		return nil
	}
	return function()
}
func (ns *captureNetNS) NetnsID() (int, error) {
	if ns == nil || !ns.captureNS.IsOpen() {
		return 0, errors.New("capture network namespace is closed")
	}
	return netlink.GetNetNsIdByFd(int(ns.captureNS))
}

func (ns *captureNetNS) Close() error {
	if ns == nil {
		return nil
	}
	ns.mu.Lock()
	if ns.closed {
		ns.mu.Unlock()
		return nil
	}
	ns.closed = true
	hostNS, captureNS := ns.hostNS, ns.captureNS
	ns.hostNS, ns.captureNS = netns.None(), netns.None()
	createdHostLink, createdNamespace, token, hostSysctls := ns.createdHostLink, ns.createdNamespace, ns.token, ns.hostSysctls
	ns.mu.Unlock()
	var errs []error
	if hostNS.IsOpen() {
		runtime.LockOSThread()
		if err := netns.Set(hostNS); err != nil {
			errs = append(errs, err)
		} else {
			if hostSysctls != nil {
				if err := hostSysctls.Close(); err != nil {
					errs = append(errs, err)
				}
			}
			if createdHostLink {
				if err := deleteOwnedLink(captureHostLink, token); err != nil {
					errs = append(errs, err)
				}
			}
		}
		runtime.UnlockOSThread()
	}
	if createdNamespace {
		identity, err := identifyNetworkNamespace(captureNS)
		if err != nil {
			errs = append(errs, err)
		} else if err := deleteNamedNetworkNamespace(captureNetNSName, identity); err != nil {
			errs = append(errs, err)
		}
	}
	if captureNS.IsOpen() {
		if err := captureNS.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hostNS.IsOpen() {
		if err := hostNS.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func identifyNetworkNamespace(namespace netns.NsHandle) (networkNamespaceIdentity, error) {
	if !namespace.IsOpen() {
		return networkNamespaceIdentity{}, errors.New("network namespace handle is closed")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(namespace), &stat); err != nil {
		return networkNamespaceIdentity{}, fmt.Errorf("inspect network namespace identity: %w", err)
	}
	identity := networkNamespaceIdentity{device: uint64(stat.Dev), inode: stat.Ino}
	if !identity.valid() {
		return networkNamespaceIdentity{}, errors.New("network namespace has an invalid kernel identity")
	}
	return identity, nil
}

func deleteNamedNetworkNamespace(name string, expected networkNamespaceIdentity) error {
	if !expected.valid() {
		return errors.New("refuse to delete named network namespace without a kernel identity")
	}
	current, err := netns.GetFromName(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open named network namespace %s: %w", name, err)
	}
	actual, identityErr := identifyNetworkNamespace(current)
	closeErr := current.Close()
	if identityErr != nil {
		return identityErr
	}
	if closeErr != nil {
		return fmt.Errorf("close named network namespace %s: %w", name, closeErr)
	}
	if actual != expected {
		return fmt.Errorf("refuse to delete named network namespace %s: kernel identity changed", name)
	}
	if err := netns.DeleteNamed(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete named network namespace %s: %w", name, err)
	}
	return nil
}

func withNetNSHandle(target netns.NsHandle, function func() error) (err error) {
	if !target.IsOpen() {
		return errors.New("network namespace handle is closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	host, err := netns.Get()
	if err != nil {
		return err
	}
	defer host.Close()
	if err := netns.Set(target); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, netns.Set(host)) }()
	if function == nil {
		return nil
	}
	return function()
}

func deleteOwnedLink(name, token string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if isMissingNetlinkError(err) {
			return nil
		}
		return err
	}
	if link.Attrs() == nil || link.Attrs().Alias != token {
		return fmt.Errorf("refuse to delete link %s without matching ownership token", name)
	}
	if err := netlink.LinkDel(link); err != nil && !isMissingNetlinkError(err) {
		return fmt.Errorf("delete owned link %s: %w", name, err)
	}
	return nil
}
func isMissingNetlinkError(err error) bool {
	var linkNotFound netlink.LinkNotFoundError
	return err == nil || errors.As(err, &linkNotFound) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH)
}
