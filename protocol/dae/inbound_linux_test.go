//go:build linux && !android && with_dae

package dae

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/ebpfinbound"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type testNetworkManager struct {
	adapter.NetworkManager
	access          sync.Mutex
	mark            uint32
	registerCount   int
	unregisterCount int
}

func (*testNetworkManager) InterfaceFinder() control.InterfaceFinder { return nil }

func (m *testNetworkManager) RegisterAutoRedirectOutputMark(mark uint32) error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.mark != 0 {
		return errors.New("output mark is already registered")
	}
	m.mark = mark
	m.registerCount++
	return nil
}

func (m *testNetworkManager) UnregisterAutoRedirectOutputMark(mark uint32) error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.mark != mark {
		return errors.New("output mark ownership mismatch")
	}
	m.mark = 0
	m.unregisterCount++
	return nil
}

func (m *testNetworkManager) AutoRedirectOutputMark() uint32 {
	m.access.Lock()
	defer m.access.Unlock()
	return m.mark
}

type testListenerSet struct {
	tcp4 *net.TCPListener
	tcp6 *net.TCPListener
	udp  *net.UDPConn
	port uint16
}

func (s *testListenerSet) TCP4() *net.TCPListener { return s.tcp4 }
func (s *testListenerSet) TCP6() *net.TCPListener { return s.tcp6 }
func (s *testListenerSet) UDP() *net.UDPConn      { return s.udp }
func (s *testListenerSet) Port() uint16           { return s.port }

func newTestListenerSet(t *testing.T) *testListenerSet {
	t.Helper()
	tcp4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tcp6, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		_ = tcp4.Close()
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		_ = tcp4.Close()
		_ = tcp6.Close()
		t.Fatal(err)
	}
	return &testListenerSet{
		tcp4: tcp4,
		tcp6: tcp6,
		udp:  udp,
		port: uint16(tcp4.Addr().(*net.TCPAddr).Port),
	}
}

type testRuntime struct {
	listeners *testListenerSet
	lookup    ebpfinbound.Metadata

	access     sync.Mutex
	closeCount int
	closeOnce  sync.Once
}

func (r *testRuntime) Listeners() ebpfinbound.ListenerSet { return r.listeners }

func (r *testRuntime) LookupMetadata(context.Context, ebpfinbound.Flow) (ebpfinbound.Metadata, bool, error) {
	return r.lookup, true, nil
}

func (*testRuntime) OutputMark() uint32 { return ebpfinbound.DefaultOutputMark }

func (r *testRuntime) Status() ebpfinbound.Status {
	return ebpfinbound.Status{Ready: true, OutputMark: r.OutputMark(), Port: r.listeners.Port()}
}

func (r *testRuntime) Close() error {
	r.closeOnce.Do(func() {
		r.access.Lock()
		r.closeCount++
		r.access.Unlock()
		_ = r.listeners.tcp4.Close()
		_ = r.listeners.tcp6.Close()
		_ = r.listeners.udp.Close()
	})
	return nil
}

func (r *testRuntime) closes() int {
	r.access.Lock()
	defer r.access.Unlock()
	return r.closeCount
}

func TestRuntimeCoordinatorHandsOffOneDataplane(t *testing.T) {
	manager := &testNetworkManager{}
	runtime := &testRuntime{listeners: newTestListenerSet(t)}
	factoryCalls := 0
	coordinator := &runtimeCoordinator{newRuntime: func(context.Context, ebpfinbound.Options) (ebpfinbound.Runtime, error) {
		factoryCalls++
		return runtime, nil
	}}
	first := newTestInbound(t, coordinator, manager, "dae-in", 0)
	second := newTestInbound(t, coordinator, manager, "dae-in", 0)

	if err := first.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	if err := second.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	if factoryCalls != 1 {
		t.Fatalf("provider factory called %d times, want 1", factoryCalls)
	}
	coordinator.access.Lock()
	lease := coordinator.lease
	coordinator.access.Unlock()
	target := coordinator.acquireTarget(lease)
	if target == nil || target.inbound != second {
		t.Fatal("new inbound did not become the active dispatch target")
	}
	target.done()

	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	target = coordinator.acquireTarget(lease)
	if target == nil || target.inbound != first {
		t.Fatal("surviving inbound was not restored after active replacement closed")
	}
	target.done()
	if runtime.closes() != 0 {
		t.Fatal("shared provider closed while one member remained")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.closes() != 1 {
		t.Fatalf("provider close count = %d, want 1", runtime.closes())
	}
	if manager.AutoRedirectOutputMark() != 0 || manager.registerCount != 1 || manager.unregisterCount != 1 {
		t.Fatalf("output mark lease was not balanced: mark=%#x register=%d unregister=%d", manager.AutoRedirectOutputMark(), manager.registerCount, manager.unregisterCount)
	}
}

func TestRuntimeCoordinatorRejectsAmbiguousOwnership(t *testing.T) {
	manager := &testNetworkManager{}
	runtime := &testRuntime{listeners: newTestListenerSet(t)}
	coordinator := &runtimeCoordinator{newRuntime: func(context.Context, ebpfinbound.Options) (ebpfinbound.Runtime, error) {
		return runtime, nil
	}}
	first := newTestInbound(t, coordinator, manager, "dae-in", 0)
	if err := first.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	differentTag := newTestInbound(t, coordinator, manager, "other-dae", 0)
	if err := differentTag.Start(adapter.StartStateStart); err == nil || !strings.Contains(err.Error(), "one dae eBPF inbound tag") {
		t.Fatalf("different-tag start error = %v", err)
	}
	differentConfig := newTestInbound(t, coordinator, manager, "dae-in", 23456)
	if err := differentConfig.Start(adapter.StartStateStart); err == nil || !strings.Contains(err.Error(), "process restart") {
		t.Fatalf("different-config start error = %v", err)
	}
	if err := differentTag.Close(); err != nil {
		t.Fatal(err)
	}
	if err := differentConfig.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeCloseWaitsForDispatch(t *testing.T) {
	manager := &testNetworkManager{}
	runtime := &testRuntime{listeners: newTestListenerSet(t)}
	coordinator := &runtimeCoordinator{newRuntime: func(context.Context, ebpfinbound.Options) (ebpfinbound.Runtime, error) {
		return runtime, nil
	}}
	inbound := newTestInbound(t, coordinator, manager, "dae-in", 0)
	if err := inbound.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	coordinator.access.Lock()
	lease := coordinator.lease
	coordinator.access.Unlock()
	target := coordinator.acquireTarget(lease)
	if target == nil {
		t.Fatal("failed to acquire dispatch target")
	}
	closed := make(chan error, 1)
	go func() { closed <- inbound.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("runtime closed with a dispatch in flight: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	target.done()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not close after dispatch completed")
	}
}

func TestMetadataMapsVerifiedProcessFacts(t *testing.T) {
	manager := &testNetworkManager{}
	coordinator := &runtimeCoordinator{}
	inbound := newTestInbound(t, coordinator, manager, "dae-in", 0)
	startTime, err := readProcessStartTime("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	runtime := &testRuntime{
		listeners: newTestListenerSet(t),
		lookup: ebpfinbound.Metadata{
			ProcessID:        uint32(os.Getpid()),
			ProcessName:      "sing-box-test",
			ProcessStartTime: startTime,
			ProcessUID:       uint32(os.Getuid()),
			HasProcessUID:    true,
			SourceMAC:        [6]byte{0x02, 0, 0, 0, 0, 1},
			HasSourceMAC:     true,
			DSCP:             42,
		},
	}
	metadata := inbound.lookupMetadata(
		context.Background(),
		runtime,
		"tcp",
		M.SocksaddrFromNetIP(netip.MustParseAddrPort("192.0.2.1:1234")),
		M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.51.100.1:443")),
	)
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.ProcessID != uint32(os.Getpid()) {
		t.Fatalf("process metadata = %+v", metadata.ProcessInfo)
	}
	if len(metadata.ProcessInfo.ProcessNames) != 1 || metadata.ProcessInfo.ProcessNames[0] != "sing-box-test" {
		t.Fatalf("process names = %v", metadata.ProcessInfo.ProcessNames)
	}
	if len(metadata.ProcessInfo.ProcessPaths) != 1 || metadata.ProcessInfo.ProcessPaths[0] == "" {
		t.Fatalf("verified process paths = %v", metadata.ProcessInfo.ProcessPaths)
	}
	if metadata.ProcessInfo.UserId != int32(os.Getuid()) || metadata.SourceMACAddress.String() != "02:00:00:00:00:01" || metadata.DSCP != 42 {
		t.Fatalf("mapped metadata = %+v", metadata)
	}
	if path := verifiedProcessPath(uint32(os.Getpid()), startTime+1); path != "" {
		t.Fatalf("accepted process path with the wrong start time: %s", path)
	}
	_ = inbound.Close()
	_ = runtime.Close()
}

func newTestInbound(t *testing.T, coordinator *runtimeCoordinator, manager *testNetworkManager, tag string, port uint16) *Inbound {
	t.Helper()
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), manager)
	created, err := NewInbound(ctx, nil, log.NewNOPFactory().Logger(), tag, option.DAEInboundOptions{
		TProxyPort:   port,
		LANInterface: []string{"test-lan0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	inbound := created.(*Inbound)
	inbound.coordinator = coordinator
	return inbound
}
