//go:build with_gvisor && darwin

package tailscale

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var systemRouteMessageSeq atomic.Int32

type systemRouteFamily uint8

const (
	systemRouteIPv4 systemRouteFamily = 4
	systemRouteIPv6 systemRouteFamily = 6
)

type systemRoute struct {
	family  systemRouteFamily
	gateway netip.Addr
	index   int
}

type darwinSystemRouteManager struct {
	name string

	mu     sync.Mutex
	routes map[systemRouteFamily]systemRoute
	closed bool
}

func newSystemRouteManager(name string) systemRouteManager {
	return &darwinSystemRouteManager{
		name:   name,
		routes: make(map[systemRouteFamily]systemRoute),
	}
}

// Update installs or removes only the two interface-scoped default routes.
// The route is an interface route (RTAX_GATEWAY=LinkAddr), with the local
// Tailscale address supplied as RTAX_IFA. This is the form macOS accepts for
// an address-less/point-to-point utun, especially for IPv6: using the ULA
// address as an ordinary gateway is rejected as "Network is unreachable".
// A missing address simply disables that address family; this is important
// when a network has IPv4 only or when Tailscale is still converging.
func (r *darwinSystemRouteManager) Update(enabled bool, ip4, ip6 netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}

	if4, if6, err := r.interfaceIndexes()
	if err != nil {
		if enabled {
			return err
		}
		// If the interface has already disappeared, the kernel has removed
		// its scoped routes along with it. Forget our bookkeeping.
		clear(r.routes)
		return nil
	}

	want := map[systemRouteFamily]systemRoute{}
	if enabled && ip4.Is4() {
		want[systemRouteIPv4] = systemRoute{family: systemRouteIPv4, gateway: ip4.Unmap(), index: if4}
	}
	if enabled && ip6.Is6() {
		want[systemRouteIPv6] = systemRoute{family: systemRouteIPv6, gateway: ip6.Unmap(), index: if6}
	}

	var updateErr error
	for _, family := range []systemRouteFamily{systemRouteIPv4, systemRouteIPv6} {
		old, hadOld := r.routes[family]
		newRoute, wantsNew := want[family]
		if hadOld && (!wantsNew || old.gateway != newRoute.gateway || old.index != newRoute.index) {
			if err := deleteScopedDefault(old); err != nil && !isRouteGone(err) {
				updateErr = errors.Join(updateErr, err)
				continue
			}
			delete(r.routes, family)
			hadOld = false
		}
		if !wantsNew || hadOld {
			continue
		}
		if err := addScopedDefault(newRoute); err != nil && !errors.Is(err, unix.EEXIST) {
			updateErr = errors.Join(updateErr, err)
			continue
		}
		// EEXIST is safe to adopt: the route key includes the destination,
		// address family, scope and interface, and the gateway is the local
		// Tailscale address. It is normally a route left by an earlier
		// instance after a crash.
		r.routes[family] = newRoute
	}
	return updateErr
}

func (r *darwinSystemRouteManager) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var closeErr error
	for family, route := range r.routes {
		if err := deleteScopedDefault(route); err != nil && !isRouteGone(err) {
			closeErr = errors.Join(closeErr, err)
			continue
		}
		delete(r.routes, family)
	}
	return closeErr
}

func (r *darwinSystemRouteManager) interfaceIndexes() (int, int, error) {
	interfaceInfo, err := net.InterfaceByName(r.name)
	if err != nil {
		return 0, 0, err
	}
	// Both families use the same utun interface index. Keeping the two
	// return values makes the desired route state explicit and leaves room
	// for a future platform with family-specific indexes.
	return interfaceInfo.Index, interfaceInfo.Index, nil
}

func isRouteGone(err error) bool {
	return errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENXIO)
}

func addScopedDefault(r systemRoute) error {
	return executeScopedRoute(unix.RTM_ADD, r)
}

func deleteScopedDefault(r systemRoute) error {
	return executeScopedRoute(unix.RTM_DELETE, r)
}

func executeScopedRoute(messageType int, r systemRoute) error {
	message, err := scopedRouteMessage(messageType, r, uintptr(os.Getpid()), int(systemRouteMessageSeq.Add(1)))
	if err != nil {
		return err
	}
	request, err := message.Marshal()
	if err != nil {
		return err
	}
	socketFD, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socketFD)
	_ = unix.SetsockoptTimeval(socketFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	if _, err = unix.Write(socketFD, request); err != nil {
		return err
	}

	buffer := make([]byte, 4096)
	deadline := time.Now().Add(time.Second)
	for {
		n, readErr := unix.Read(socketFD, buffer)
		if readErr != nil {
			return readErr
		}
		messages, parseErr := route.ParseRIB(route.RIBTypeRoute, buffer[:n])
		if parseErr != nil {
			if time.Now().After(deadline) {
				return parseErr
			}
			continue
		}
		for _, rawMessage := range messages {
			reply, ok := rawMessage.(*route.RouteMessage)
			if !ok || reply.ID != message.ID || reply.Seq != message.Seq {
				continue
			}
			return reply.Err
		}
		if time.Now().After(deadline) {
			return os.ErrDeadlineExceeded
		}
	}
}

func scopedRouteMessage(messageType int, r systemRoute, id uintptr, seq int) (route.RouteMessage, error) {
	var destination, mask, interfaceAddress route.Addr
	switch r.family {
	case systemRouteIPv4:
		destination = &route.Inet4Addr{}
		mask = &route.Inet4Addr{}
		interfaceAddress = &route.Inet4Addr{IP: r.gateway.As4()}
	case systemRouteIPv6:
		destination = &route.Inet6Addr{}
		mask = &route.Inet6Addr{}
		interfaceAddress = &route.Inet6Addr{IP: r.gateway.As16()}
	default:
		return route.RouteMessage{}, unix.EAFNOSUPPORT
	}

	flags := unix.RTF_STATIC | unix.RTF_IFSCOPE
	if messageType == unix.RTM_ADD {
		flags |= unix.RTF_UP
	}
	return route.RouteMessage{
		Type:    messageType,
		Version: unix.RTM_VERSION,
		Flags:   flags,
		Index:   r.index,
		ID:      id,
		Seq:     seq,
		Addrs: []route.Addr{
			syscall.RTAX_DST:     destination,
			syscall.RTAX_GATEWAY: &route.LinkAddr{Index: r.index},
			syscall.RTAX_NETMASK: mask,
			syscall.RTAX_IFA:     interfaceAddress,
		},
	}, nil
}
