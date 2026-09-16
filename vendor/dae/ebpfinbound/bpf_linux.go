//go:build linux && !dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

const (
	listenerMapTCP4 = uint32(0)
	listenerMapUDP  = uint32(1)
	listenerMapTCP6 = uint32(2)

	tcpMetadataLookupAttempts = 3
	tcpMetadataLookupDelay    = 2 * time.Millisecond
	routingHandoffTimeout     = 10 * time.Second
)

var captureProgramNames = []string{
	"tproxy_lan_egress_l2", "tproxy_lan_egress_l3",
	"tproxy_lan_ingress_l2", "tproxy_lan_ingress_l3",
	"tproxy_wan_ingress_l2", "tproxy_wan_ingress_l3",
	"tproxy_wan_egress_l2", "tproxy_wan_egress_l3",
	"tproxy_dae0peer_ingress", "tproxy_dae0_ingress",
	"tproxy_wan_cg_sock_create", "tproxy_wan_cg_sock_release",
	"tproxy_wan_cg_connect4", "tproxy_wan_cg_connect6",
	"tproxy_wan_cg_sendmsg4", "tproxy_wan_cg_sendmsg6",
}

var forbiddenPolicyMaps = []string{
	"outbound_connectivity_map", "unused_lpm_type", "lpm_array_map",
	"routing_map", "routing_meta_map", "domain_routing_map",
}

type captureObjects struct {
	collection *ebpf.Collection

	ListenSocketMap   *ebpf.Map
	ConnStateMap      *ebpf.Map
	RoutingHandoffMap *ebpf.Map

	TproxyLanEgressL2      *ebpf.Program
	TproxyLanEgressL3      *ebpf.Program
	TproxyLanIngressL2     *ebpf.Program
	TproxyLanIngressL3     *ebpf.Program
	TproxyWanIngressL2     *ebpf.Program
	TproxyWanIngressL3     *ebpf.Program
	TproxyWanEgressL2      *ebpf.Program
	TproxyWanEgressL3      *ebpf.Program
	TproxyDae0peerIngress  *ebpf.Program
	TproxyDae0Ingress      *ebpf.Program
	TproxyWanCgSockCreate  *ebpf.Program
	TproxyWanCgSockRelease *ebpf.Program
	TproxyWanCgConnect4    *ebpf.Program
	TproxyWanCgConnect6    *ebpf.Program
	TproxyWanCgSendmsg4    *ebpf.Program
	TproxyWanCgSendmsg6    *ebpf.Program
}

func (o *captureObjects) Close() error {
	if o == nil || o.collection == nil {
		return nil
	}
	o.collection.Close()
	o.collection = nil
	return nil
}

func loadCaptureBPF(ns *captureNetNS, config CaptureConfig) (*captureObjects, error) {
	if ns == nil || ns.hostLink == nil || ns.peerLink == nil {
		return nil, errors.New("capture network namespace is not initialized")
	}
	netnsID, err := ns.NetnsID()
	if err != nil {
		return nil, fmt.Errorf("get capture network namespace ID: %w", err)
	}
	peerMAC := [6]byte{}
	if address := ns.peerLink.Attrs().HardwareAddr; len(address) == len(peerMAC) {
		copy(peerMAC[:], address)
	}
	hasCurrentTask := uint8(0)
	if err := features.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetCurrentTask); err == nil {
		hasCurrentTask = 1
	} else if ns.log != nil {
		ns.log.Warn("bpf_get_current_task unavailable; process names may be truncated", "error", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}
	parameter := bpfDaeParam{
		TproxyPort:           hostToNetwork32(uint32(config.TProxyPort)),
		ControlPlanePid:      uint32(os.Getpid()),
		Dae0Ifindex:          uint32(ns.hostLink.Attrs().Index),
		DaeNetnsId:           uint32(netnsID),
		Dae0peerMac:          peerMAC,
		UseRedirectPeer:      0,
		HasBpfGetCurrentTask: hasCurrentTask,
		DaeSocketMark:        config.OutputMark,
	}
	variable, exists := spec.Variables["PARAM"]
	if !exists || variable == nil {
		return nil, errors.New("embedded BPF collection is missing PARAM")
	}
	if err := variable.Set(parameter); err != nil {
		return nil, fmt.Errorf("rewrite BPF PARAM: %w", err)
	}
	if err := pruneCaptureSpec(spec); err != nil {
		return nil, err
	}
	for name, mapSpec := range spec.Maps {
		if mapSpec == nil {
			continue
		}
		mapSpec.Pinning = ebpf.PinNone
		if name == "conn_state_map" {
			mapSpec.MaxEntries = config.ConnectionStateMapEntries
		}
	}

	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return nil, err
	}
	objects := &captureObjects{collection: collection}
	objects.ListenSocketMap = collection.Maps["listen_socket_map"]
	objects.ConnStateMap = collection.Maps["conn_state_map"]
	objects.RoutingHandoffMap = collection.Maps["routing_handoff_map"]
	objects.TproxyLanEgressL2 = collection.Programs["tproxy_lan_egress_l2"]
	objects.TproxyLanEgressL3 = collection.Programs["tproxy_lan_egress_l3"]
	objects.TproxyLanIngressL2 = collection.Programs["tproxy_lan_ingress_l2"]
	objects.TproxyLanIngressL3 = collection.Programs["tproxy_lan_ingress_l3"]
	objects.TproxyWanIngressL2 = collection.Programs["tproxy_wan_ingress_l2"]
	objects.TproxyWanIngressL3 = collection.Programs["tproxy_wan_ingress_l3"]
	objects.TproxyWanEgressL2 = collection.Programs["tproxy_wan_egress_l2"]
	objects.TproxyWanEgressL3 = collection.Programs["tproxy_wan_egress_l3"]
	objects.TproxyDae0peerIngress = collection.Programs["tproxy_dae0peer_ingress"]
	objects.TproxyDae0Ingress = collection.Programs["tproxy_dae0_ingress"]
	objects.TproxyWanCgSockCreate = collection.Programs["tproxy_wan_cg_sock_create"]
	objects.TproxyWanCgSockRelease = collection.Programs["tproxy_wan_cg_sock_release"]
	objects.TproxyWanCgConnect4 = collection.Programs["tproxy_wan_cg_connect4"]
	objects.TproxyWanCgConnect6 = collection.Programs["tproxy_wan_cg_connect6"]
	objects.TproxyWanCgSendmsg4 = collection.Programs["tproxy_wan_cg_sendmsg4"]
	objects.TproxyWanCgSendmsg6 = collection.Programs["tproxy_wan_cg_sendmsg6"]

	if objects.ListenSocketMap == nil || objects.ConnStateMap == nil || objects.RoutingHandoffMap == nil {
		_ = objects.Close()
		return nil, errors.New("capture collection is missing required metadata or listener maps")
	}
	for _, name := range captureProgramNames {
		if collection.Programs[name] == nil {
			_ = objects.Close()
			return nil, fmt.Errorf("capture collection is missing program %q", name)
		}
	}
	return objects, nil
}

func pruneCaptureSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("nil BPF collection specification")
	}
	allowedPrograms := make(map[string]struct{}, len(captureProgramNames))
	for _, name := range captureProgramNames {
		allowedPrograms[name] = struct{}{}
		if spec.Programs[name] == nil {
			return fmt.Errorf("embedded BPF collection is missing capture program %q", name)
		}
	}
	for name := range spec.Programs {
		if _, keep := allowedPrograms[name]; !keep {
			delete(spec.Programs, name)
		}
	}
	requiredMaps := map[string]struct{}{
		"listen_socket_map": {}, "conn_state_map": {}, "routing_handoff_map": {},
	}
	for _, program := range spec.Programs {
		for _, instruction := range program.Instructions {
			reference := instruction.Reference()
			if reference == "" {
				continue
			}
			if _, exists := spec.Maps[reference]; exists {
				requiredMaps[reference] = struct{}{}
			}
		}
	}
	for name := range spec.Maps {
		if strings.HasPrefix(name, ".") {
			continue
		}
		if _, keep := requiredMaps[name]; !keep {
			delete(spec.Maps, name)
		}
	}
	for _, name := range forbiddenPolicyMaps {
		if spec.Maps[name] != nil {
			return fmt.Errorf("policy map %q remained after capture-only pruning", name)
		}
	}
	return nil
}

func captureSpecNames(spec *ebpf.CollectionSpec) (programs, maps []string) {
	if spec == nil {
		return nil, nil
	}
	for name := range spec.Programs {
		programs = append(programs, name)
	}
	for name := range spec.Maps {
		maps = append(maps, name)
	}
	sort.Strings(programs)
	sort.Strings(maps)
	return programs, maps
}

func hostToNetwork32(value uint32) uint32 {
	var buffer [4]byte
	binary.BigEndian.PutUint32(buffer[:], value)
	return binary.NativeEndian.Uint32(buffer[:])
}
func hostToNetwork16(value uint16) uint16 {
	var buffer [2]byte
	binary.BigEndian.PutUint16(buffer[:], value)
	return binary.NativeEndian.Uint16(buffer[:])
}

func bpfKeyFromFlow(flow Flow) bpfTuplesKey {
	var key bpfTuplesKey
	key.Sip.U6Addr8 = flow.Source.Addr().As16()
	key.Dip.U6Addr8 = flow.Destination.Addr().As16()
	key.Sport = hostToNetwork16(flow.Source.Port())
	key.Dport = hostToNetwork16(flow.Destination.Port())
	switch flow.Network {
	case NetworkTCP:
		key.L4proto = unix.IPPROTO_TCP
	case NetworkUDP:
		key.L4proto = unix.IPPROTO_UDP
	}
	return key
}

func lookupFlowMetadata(ctx context.Context, objects *captureObjects, flow Flow) (Metadata, bool, error) {
	if objects == nil || objects.ConnStateMap == nil {
		return Metadata{}, false, errors.New("capture BPF maps are closed")
	}
	attempts, delay := 1, time.Duration(0)
	if flow.Network == NetworkTCP {
		attempts, delay = tcpMetadataLookupAttempts, tcpMetadataLookupDelay
	}
	key := bpfKeyFromFlow(flow)
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		metadata, found, err := lookupMetadataOnce(objects, &key)
		if err == nil || !errors.Is(err, ebpf.ErrKeyNotExist) {
			if found {
				enrichNumericProcessMetadata(&metadata)
			}
			return metadata, found, err
		}
		lastErr = err
		if attempt == attempts-1 || delay <= 0 {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Metadata{}, false, ctx.Err()
		case <-timer.C:
		}
	}
	if errors.Is(lastErr, ebpf.ErrKeyNotExist) {
		return Metadata{}, false, nil
	}
	return Metadata{}, false, lastErr
}

func lookupMetadataOnce(objects *captureObjects, key *bpfTuplesKey) (Metadata, bool, error) {
	var state bpfConnState
	if err := objects.ConnStateMap.Lookup(key, &state); err == nil {
		if state.Meta.Data.HasRouting != 0 {
			return metadataFromKernel(state.Pid, state.Pname, state.Mac, state.Meta.Data.Dscp), true, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return Metadata{}, false, fmt.Errorf("read conn_state_map: %w", err)
	}
	if objects.RoutingHandoffMap == nil {
		return Metadata{}, false, ebpf.ErrKeyNotExist
	}
	var handoff bpfRoutingHandoffEntry
	if err := objects.RoutingHandoffMap.Lookup(key, &handoff); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Metadata{}, false, ebpf.ErrKeyNotExist
		}
		return Metadata{}, false, fmt.Errorf("read routing_handoff_map: %w", err)
	}
	now, err := monotonicNowNano()
	if err != nil {
		return Metadata{}, false, err
	}
	if staleTimestamp(now, handoff.LastSeenNs, routingHandoffTimeout) {
		_ = objects.RoutingHandoffMap.Delete(key)
		return Metadata{}, false, ebpf.ErrKeyNotExist
	}
	return metadataFromKernel(handoff.Result.Pid, handoff.Result.Pname, handoff.Result.Mac, handoff.Result.Dscp), true, nil
}

func metadataFromKernel(pid uint32, processName [16]uint8, sourceMAC [6]uint8, dscp uint8) Metadata {
	metadata := Metadata{ProcessID: pid, ProcessName: string(bytes.TrimRight(processName[:], "\x00")), SourceMAC: sourceMAC, DSCP: dscp}
	for _, value := range sourceMAC {
		if value != 0 {
			metadata.HasSourceMAC = true
			break
		}
	}
	return metadata
}

func monotonicNowNano() (uint64, error) {
	var timestamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &timestamp); err != nil {
		return 0, fmt.Errorf("read monotonic clock: %w", err)
	}
	return uint64(timestamp.Nano()), nil
}
func staleTimestamp(now, lastSeen uint64, timeout time.Duration) bool {
	if lastSeen == 0 {
		return true
	}
	if now <= lastSeen {
		return false
	}
	return now-lastSeen > uint64(timeout.Nanoseconds())
}

func publishListenersOnce(objects *captureObjects, listeners ListenerSet) ([]*os.File, error) {
	if objects == nil || objects.ListenSocketMap == nil {
		return nil, errors.New("listener sockmap is unavailable")
	}
	if listeners == nil || listeners.TCP4() == nil || listeners.TCP6() == nil || listeners.UDP() == nil {
		return nil, errors.New("complete TCP4, TCP6, and UDP listener set is required")
	}
	files := make([]*os.File, 0, 3)
	closeFiles := func() {
		for _, file := range files {
			if file != nil {
				_ = file.Close()
			}
		}
	}
	for _, open := range []func() (*os.File, error){
		func() (*os.File, error) { return duplicateTCPListener(listeners.TCP4()) },
		func() (*os.File, error) { return duplicateUDPConn(listeners.UDP()) },
		func() (*os.File, error) { return duplicateTCPListener(listeners.TCP6()) },
	} {
		file, err := open()
		if err != nil {
			closeFiles()
			return nil, err
		}
		files = append(files, file)
	}
	for index, key := range []uint32{listenerMapTCP4, listenerMapUDP, listenerMapTCP6} {
		value := uint64(files[index].Fd())
		if err := objects.ListenSocketMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
			closeFiles()
			return nil, fmt.Errorf("publish listener key %d: %w", key, err)
		}
	}
	return files, nil
}
