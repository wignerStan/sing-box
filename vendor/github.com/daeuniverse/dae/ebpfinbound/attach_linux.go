//go:build linux && !dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type ownedTCAttachment struct{ record ownedAttachmentRecord }

var errTCFilterNotFound = errors.New("capture TC filter not found")

func (r *captureRuntime) attachDatapath() ([]ownedTCAttachment, []func() error, error) {
	if r.bpf == nil || r.netns == nil {
		return nil, nil, errors.New("capture runtime is closed")
	}
	if err := r.configureKernel(); err != nil {
		return nil, nil, fmt.Errorf("configure capture kernel settings: %w", err)
	}
	var records []ownedTCAttachment
	cleanup := make([]func() error, 0, 24)
	fail := func(err error) ([]ownedTCAttachment, []func() error, error) {
		return records, cleanup, err
	}
	recordAttachment := func(record ownedAttachmentRecord) error {
		if r.ownership == nil {
			return errors.New("capture ownership lease is unavailable")
		}
		return r.ownership.UpsertAttachment(record)
	}

	internalRecords, internalCleanup, err := r.attachInternalLinks(recordAttachment)
	records = append(records, internalRecords...)
	cleanup = append(cleanup, internalCleanup...)
	if err != nil {
		return fail(fmt.Errorf("attach private capture links: %w", err))
	}

	if len(r.config.WANInterfaces) > 0 {
		cgroupCleanup, attachErr := r.attachProcessMetadata()
		if attachErr != nil {
			cleanupErr := runCleanupReverse(cgroupCleanup)
			if cleanupErr != nil {
				return fail(errors.Join(fmt.Errorf("attach process metadata hooks: %w", attachErr), fmt.Errorf("roll back process metadata hooks: %w", cleanupErr)))
			}
			if r.config.RequireProcessMetadata {
				return fail(fmt.Errorf("attach required process metadata hooks: %w", attachErr))
			}
			if r.log != nil {
				r.log.Warn("process metadata hooks unavailable; process matching will degrade", "error", attachErr)
			}
		} else {
			r.processMetadataEnabled = true
			cleanup = append(cleanup, cgroupCleanup...)
		}
	}

	for _, interfaceName := range r.config.LANInterfaces {
		attached, attachedCleanup, attachErr := r.attachLANInterface(interfaceName, recordAttachment)
		records = append(records, attached...)
		cleanup = append(cleanup, attachedCleanup...)
		if attachErr != nil {
			return fail(fmt.Errorf("attach LAN interface %s: %w", interfaceName, attachErr))
		}
	}
	for _, interfaceName := range r.config.WANInterfaces {
		attached, attachedCleanup, attachErr := r.attachWANInterface(interfaceName, recordAttachment)
		records = append(records, attached...)
		cleanup = append(cleanup, attachedCleanup...)
		if attachErr != nil {
			return fail(fmt.Errorf("attach WAN interface %s: %w", interfaceName, attachErr))
		}
	}
	return records, cleanup, nil
}

func (r *captureRuntime) configureKernel() error {
	if !r.config.AutoConfigureKernel || r.netns == nil || r.netns.hostSysctls == nil {
		return nil
	}
	manager := r.netns.hostSysctls
	if err := manager.Set("/proc/sys/net/ipv4/conf/all/rp_filter", "0"); err != nil {
		return err
	}
	if err := manager.Set("/proc/sys/net/ipv4/conf/all/arp_filter", "0"); err != nil {
		return err
	}
	if len(r.config.LANInterfaces) > 0 {
		for _, setting := range []struct{ path, value string }{
			{"/proc/sys/net/ipv4/ip_forward", "1"},
			{"/proc/sys/net/ipv4/conf/all/src_valid_mark", "1"},
			{"/proc/sys/net/ipv4/conf/default/src_valid_mark", "1"},
			{"/proc/sys/net/ipv6/conf/all/forwarding", "1"},
		} {
			if err := manager.Set(setting.path, setting.value); err != nil {
				if strings.Contains(setting.path, "/ipv6/") && errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
		}
	}
	for _, interfaceName := range r.config.LANInterfaces {
		for _, setting := range []struct{ family, key, value string }{
			{"ipv4", "forwarding", "1"},
			{"ipv4", "send_redirects", "0"},
			{"ipv4", "rp_filter", "0"},
			{"ipv6", "forwarding", "1"},
		} {
			path, err := interfaceSysctlPath(setting.family, interfaceName, setting.key)
			if err != nil {
				return err
			}
			if err := manager.Set(path, setting.value); err != nil {
				if setting.family == "ipv6" && errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
		}
	}
	if len(r.config.LANInterfaces) > 0 {
		for _, interfaceName := range r.config.WANInterfaces {
			path, err := interfaceSysctlPath("ipv6", interfaceName, "accept_ra")
			if err != nil {
				return err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if strings.TrimSpace(string(raw)) == "1" {
				if err := manager.Set(path, "2"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r *captureRuntime) attachLANInterface(interfaceName string, recordAttachment func(ownedAttachmentRecord) error) ([]ownedTCAttachment, []func() error, error) {
	link, err := captureInterface(interfaceName)
	if err != nil {
		return nil, nil, err
	}
	ingressProgram, egressProgram := r.bpf.TproxyLanIngressL3, r.bpf.TproxyLanEgressL3
	ingressName, egressName := "dae_cap_li_l3", "dae_cap_le_l3"
	if linkUsesEthernetHeader(link) {
		ingressProgram, egressProgram = r.bpf.TproxyLanIngressL2, r.bpf.TproxyLanEgressL2
		ingressName, egressName = "dae_cap_li_l2", "dae_cap_le_l2"
	}
	return attachInterfacePair(link, false, recordAttachment,
		newTCFilter(link, netlink.HANDLE_MIN_INGRESS, captureUserTCMajor, 0x101, 2, ingressName, ingressProgram),
		newTCFilter(link, netlink.HANDLE_MIN_EGRESS, captureUserTCMajor, 0x102, 1, egressName, egressProgram),
	)
}

func (r *captureRuntime) attachWANInterface(interfaceName string, recordAttachment func(ownedAttachmentRecord) error) ([]ownedTCAttachment, []func() error, error) {
	link, err := captureInterface(interfaceName)
	if err != nil {
		return nil, nil, err
	}
	if link.Attrs().Index == 1 || link.Attrs().Name == "lo" {
		return nil, nil, errors.New("cannot attach WAN capture to loopback")
	}
	ingressProgram, egressProgram := r.bpf.TproxyWanIngressL3, r.bpf.TproxyWanEgressL3
	ingressName, egressName := "dae_cap_wi_l3", "dae_cap_we_l3"
	if linkUsesEthernetHeader(link) {
		ingressProgram, egressProgram = r.bpf.TproxyWanIngressL2, r.bpf.TproxyWanEgressL2
		ingressName, egressName = "dae_cap_wi_l2", "dae_cap_we_l2"
	}
	return attachInterfacePair(link, false, recordAttachment,
		newTCFilter(link, netlink.HANDLE_MIN_EGRESS, captureUserTCMajor, 0x201, 2, egressName, egressProgram),
		newTCFilter(link, netlink.HANDLE_MIN_INGRESS, captureUserTCMajor, 0x202, 1, ingressName, ingressProgram),
	)
}

func (r *captureRuntime) attachInternalLinks(recordAttachment func(ownedAttachmentRecord) error) ([]ownedTCAttachment, []func() error, error) {
	if r.netns.hostLink == nil || r.netns.peerLink == nil {
		return nil, nil, errors.New("private capture links are unavailable")
	}
	var records []ownedTCAttachment
	var cleanup []func() error
	peerFilter := newTCFilter(r.netns.peerLink, netlink.HANDLE_MIN_INGRESS, captureInternalTCMajor, 0x001, 0, "dae_cap_peer", r.bpf.TproxyDae0peerIngress)
	var peerRecord ownedTCAttachment
	var peerCleanup []func() error
	if err := r.netns.With(func() error {
		var attachErr error
		peerRecord, peerCleanup, attachErr = attachSingleFilter(r.netns.peerLink, true, peerFilter, recordAttachment)
		return attachErr
	}); err != nil {
		if peerRecord.record.Interface != "" {
			records = append(records, peerRecord)
		}
		cleanup = append(cleanup, peerCleanup...)
		return records, cleanup, err
	}
	records = append(records, peerRecord)
	cleanup = append(cleanup, peerCleanup...)

	hostFilter := newTCFilter(r.netns.hostLink, netlink.HANDLE_MIN_INGRESS, captureInternalTCMajor, 0x002, 0, "dae_cap_host", r.bpf.TproxyDae0Ingress)
	hostRecord, hostCleanup, err := attachSingleFilter(r.netns.hostLink, false, hostFilter, recordAttachment)
	if hostRecord.record.Interface != "" {
		records = append(records, hostRecord)
	}
	cleanup = append(cleanup, hostCleanup...)
	if err != nil {
		return records, cleanup, err
	}
	return records, cleanup, nil
}

func (r *captureRuntime) attachProcessMetadata() ([]func() error, error) {
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return nil, err
	}
	programs := []struct {
		program *ebpf.Program
		attach  ebpf.AttachType
	}{
		{r.bpf.TproxyWanCgSockCreate, ebpf.AttachCGroupInetSockCreate},
		{r.bpf.TproxyWanCgSockRelease, ebpf.AttachCgroupInetSockRelease},
		{r.bpf.TproxyWanCgConnect4, ebpf.AttachCGroupInet4Connect},
		{r.bpf.TproxyWanCgConnect6, ebpf.AttachCGroupInet6Connect},
		{r.bpf.TproxyWanCgSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{r.bpf.TproxyWanCgSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
	}
	cleanup := make([]func() error, 0, len(programs))
	for _, item := range programs {
		if item.program == nil {
			return cleanup, errors.New("capture collection is missing a process metadata hook")
		}
		attached, err := ciliumLink.AttachCgroup(ciliumLink.CgroupOptions{Path: cgroupPath, Attach: item.attach, Program: item.program})
		if err != nil {
			return cleanup, fmt.Errorf("attach cgroup program: %w", err)
		}
		link := attached
		cleanup = append(cleanup, link.Close)
	}
	return cleanup, nil
}

func captureInterface(name string) (netlink.Link, error) {
	if name == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	return netlink.LinkByName(name)
}

func linkUsesEthernetHeader(link netlink.Link) bool {
	if link == nil || link.Attrs() == nil {
		return false
	}
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		return false
	default:
		return true
	}
}

func newTCFilter(link netlink.Link, parent uint32, major, minor, priority uint16, name string, program *ebpf.Program) *netlink.BpfFilter {
	filter := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: parent, Handle: netlink.MakeHandle(major, minor), Protocol: unix.ETH_P_ALL, Priority: priority}, Name: name, DirectAction: true, Fd: -1}
	if program != nil {
		filter.Fd = program.FD()
		if info, err := program.Info(); err == nil {
			if id, available := info.ID(); available {
				filter.Id = int(id)
			}
		}
	}
	return filter
}

func attachInterfacePair(link netlink.Link, inNetNS bool, recordAttachment func(ownedAttachmentRecord) error, first, second *netlink.BpfFilter) ([]ownedTCAttachment, []func() error, error) {
	var records []ownedTCAttachment
	var cleanup []func() error
	firstRecord, firstCleanup, err := attachSingleFilter(link, inNetNS, first, recordAttachment)
	if firstRecord.record.Interface != "" {
		records = append(records, firstRecord)
	}
	cleanup = append(cleanup, firstCleanup...)
	if err != nil {
		return records, cleanup, err
	}
	secondRecord, secondCleanup, err := attachSingleFilter(link, inNetNS, second, recordAttachment)
	if secondRecord.record.Interface != "" {
		records = append(records, secondRecord)
	}
	cleanup = append(cleanup, secondCleanup...)
	if err != nil {
		return records, cleanup, err
	}
	return records, cleanup, nil
}

func attachSingleFilter(link netlink.Link, inNetNS bool, filter *netlink.BpfFilter, recordAttachment func(ownedAttachmentRecord) error) (ownedTCAttachment, []func() error, error) {
	if link == nil || link.Attrs() == nil || filter == nil || filter.Fd < 0 || filter.Id <= 0 {
		return ownedTCAttachment{}, nil, errors.New("invalid BPF TC filter")
	}
	qdisc, qdiscCreated, err := ensureClsact(link)
	if err != nil {
		return ownedTCAttachment{}, nil, err
	}
	cleanupQdisc := func() error {
		remove := func() error {
			if !qdiscCreated {
				return nil
			}
			empty, err := interfaceFiltersEmpty(link)
			if err != nil {
				return fmt.Errorf("inspect owned clsact qdisc on %s: %w", link.Attrs().Name, err)
			}
			if !empty {
				return nil
			}
			if err := netlink.QdiscDel(qdisc); err != nil && !isMissingNetlinkError(err) {
				return fmt.Errorf("delete owned clsact qdisc on %s: %w", link.Attrs().Name, err)
			}
			return nil
		}
		if !inNetNS {
			return remove()
		}
		return withNamedNetNS(captureNetNSName, remove)
	}
	record := ownedAttachmentRecord{Interface: link.Attrs().Name, InNetNS: inNetNS, Parent: filter.Attrs().Parent, Handle: filter.Attrs().Handle, Priority: filter.Attrs().Priority, Name: filter.Name, ProgramID: filter.Id, QdiscCreated: qdiscCreated}
	attachment := ownedTCAttachment{record: record}
	cleanup := []func() error{cleanupQdisc}
	if recordAttachment != nil {
		if err := recordAttachment(record); err != nil {
			return attachment, cleanup, fmt.Errorf("record capture TC filter intent %s: %w", filter.Name, err)
		}
	}
	if err := assertTCSlotFree(link, filter); err != nil {
		return attachment, cleanup, err
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return attachment, cleanup, fmt.Errorf("add capture TC filter %s: %w", filter.Name, err)
	}
	cleanup = append(cleanup, func() error { return deleteOwnedFilter(record) })
	actual, err := findTCFilter(link, filter.Attrs().Parent, filter.Attrs().Handle)
	if err != nil {
		return attachment, cleanup, err
	}
	bpfActual, ok := actual.(*netlink.BpfFilter)
	if !ok || bpfActual.Name != filter.Name {
		return attachment, cleanup, fmt.Errorf("capture TC filter identity mismatch on %s", link.Attrs().Name)
	}
	record = ownedAttachmentRecord{Interface: link.Attrs().Name, InNetNS: inNetNS, Parent: bpfActual.Attrs().Parent, Handle: bpfActual.Attrs().Handle, Priority: bpfActual.Attrs().Priority, Name: bpfActual.Name, ProgramID: bpfActual.Id, QdiscCreated: qdiscCreated}
	attachment.record = record
	if recordAttachment != nil {
		if err := recordAttachment(record); err != nil {
			return attachment, cleanup, fmt.Errorf("record attached TC filter %s: %w", filter.Name, err)
		}
	}
	// Cleanup runs in reverse order: remove the filter before deciding whether
	// the clsact qdisc created for it is now empty and can be removed.
	return attachment, cleanup, nil
}

func ensureClsact(link netlink.Link) (*netlink.GenericQdisc, bool, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, false, fmt.Errorf("list qdiscs on %s: %w", link.Attrs().Name, err)
	}
	for _, qdisc := range qdiscs {
		if qdisc != nil && qdisc.Type() == "clsact" {
			return &netlink.GenericQdisc{QdiscAttrs: *qdisc.Attrs(), QdiscType: "clsact"}, false, nil
		}
	}
	qdisc := &netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}, QdiscType: "clsact"}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, false, fmt.Errorf("add clsact qdisc to %s: %w", link.Attrs().Name, err)
	}
	return qdisc, true, nil
}

func assertTCSlotFree(link netlink.Link, candidate *netlink.BpfFilter) error {
	filters, err := netlink.FilterList(link, candidate.Attrs().Parent)
	if err != nil {
		return err
	}
	for _, existing := range filters {
		if existing == nil || existing.Attrs() == nil {
			continue
		}
		attrs := existing.Attrs()
		if attrs.Handle == candidate.Attrs().Handle || (attrs.Priority == candidate.Attrs().Priority && attrs.Protocol == candidate.Attrs().Protocol) {
			return fmt.Errorf("TC slot collision on %s parent=%#x handle=%#x priority=%d with %s", link.Attrs().Name, attrs.Parent, attrs.Handle, attrs.Priority, existing.Type())
		}
	}
	return nil
}

// findTCFilter resolves one durable TC slot. Linux may normalize or allocate a
// priority when a filter is added with priority zero, while the parent and
// handle remain the stable identity selected by this runtime. Callers still
// verify the BPF name and program ID before treating the result as owned.
func findTCFilter(link netlink.Link, parent, handle uint32, _ ...uint16) (netlink.Filter, error) {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	observed := make([]string, 0, len(filters))
	for _, filter := range filters {
		if filter == nil || filter.Attrs() == nil {
			continue
		}
		attrs := filter.Attrs()
		observed = append(observed, fmt.Sprintf("%s(handle=%#x priority=%d)", filter.Type(), attrs.Handle, attrs.Priority))
		if attrs.Handle == handle {
			return filter, nil
		}
	}
	return nil, fmt.Errorf("%w on %s parent=%#x handle=%#x; observed: %s", errTCFilterNotFound, link.Attrs().Name, parent, handle, strings.Join(observed, ", "))
}

func deleteOwnedFilter(record ownedAttachmentRecord) error {
	remove := func() error {
		link, err := netlink.LinkByName(record.Interface)
		if err != nil {
			if isMissingNetlinkError(err) {
				return nil
			}
			return err
		}
		filter, err := findTCFilter(link, record.Parent, record.Handle)
		if err != nil {
			if errors.Is(err, errTCFilterNotFound) {
				return nil
			}
			return err
		}
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok || bpfFilter.Name != record.Name || bpfFilter.Id != record.ProgramID {
			return fmt.Errorf("refuse to delete TC filter on %s: ownership identity changed", record.Interface)
		}
		if err := netlink.FilterDel(filter); err != nil && !isMissingNetlinkError(err) {
			return fmt.Errorf("delete owned TC filter %s: %w", record.Name, err)
		}
		return nil
	}
	if !record.InNetNS {
		return remove()
	}
	return withNamedNetNS(captureNetNSName, remove)
}

func cleanupStaleAttachments(records []ownedAttachmentRecord) error {
	var errs []error
	for index := len(records) - 1; index >= 0; index-- {
		if err := deleteOwnedFilter(records[index]); err != nil {
			errs = append(errs, err)
		}
	}
	for index := len(records) - 1; index >= 0; index-- {
		if err := deleteOwnedQdisc(records[index]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func deleteOwnedQdisc(record ownedAttachmentRecord) error {
	if !record.QdiscCreated {
		return nil
	}
	remove := func() error {
		link, err := netlink.LinkByName(record.Interface)
		if err != nil {
			if isMissingNetlinkError(err) {
				return nil
			}
			return err
		}
		empty, err := interfaceFiltersEmpty(link)
		if err != nil {
			return fmt.Errorf("inspect filters on %s: %w", record.Interface, err)
		}
		if !empty {
			// The qdisc is no longer exclusively ours; leave it for its current
			// users after removing only the filter whose identity we recorded.
			return nil
		}
		qdiscs, err := netlink.QdiscList(link)
		if err != nil {
			return fmt.Errorf("list qdiscs on %s: %w", record.Interface, err)
		}
		for _, qdisc := range qdiscs {
			if qdisc == nil || qdisc.Type() != "clsact" {
				continue
			}
			if err := netlink.QdiscDel(qdisc); err != nil && !isMissingNetlinkError(err) {
				return fmt.Errorf("delete owned clsact qdisc on %s: %w", record.Interface, err)
			}
			return nil
		}
		return nil
	}
	if !record.InNetNS {
		return remove()
	}
	return withNamedNetNS(captureNetNSName, remove)
}

func withNamedNetNS(name string, function func() error) (err error) {
	target, err := netns.GetFromName(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer target.Close()
	return withNetNSHandle(target, function)
}

func interfaceFiltersEmpty(link netlink.Link) (bool, error) {
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			return false, err
		}
		if len(filters) != 0 {
			return false, nil
		}
	}
	return true, nil
}

func detectCgroupPath() (string, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(fields[1]), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("cgroup v2 mount not found")
}

func attachmentRecords(source []ownedTCAttachment) []ownedAttachmentRecord {
	result := make([]ownedAttachmentRecord, 0, len(source))
	for _, attachment := range source {
		result = append(result, attachment.record)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Interface != result[j].Interface {
			return result[i].Interface < result[j].Interface
		}
		if result[i].Parent != result[j].Parent {
			return result[i].Parent < result[j].Parent
		}
		return result[i].Handle < result[j].Handle
	})
	return result
}
