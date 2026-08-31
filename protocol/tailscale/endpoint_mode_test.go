//go:build with_gvisor

package tailscale

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/tailscale/tsnet"
)

type endpointTestRouteManager struct {
	mu        sync.Mutex
	closeErr  error
	closeCall int
}

func (m *endpointTestRouteManager) Update(bool, netip.Addr, netip.Addr) error { return nil }

func (m *endpointTestRouteManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCall++
	err := m.closeErr
	m.closeErr = nil
	return err
}

func TestSystemInterfaceEndpointDoesNotImplementPort(t *testing.T) {
	var endpoint adapter.Endpoint = &Endpoint{systemInterface: true}
	if _, loaded := endpoint.(tun.Port); loaded {
		t.Fatal("system-interface endpoint unexpectedly implements tun.Port")
	}
}

func TestUserspaceEndpointImplementsPort(t *testing.T) {
	var endpoint adapter.Endpoint = &userspaceEndpoint{Endpoint: &Endpoint{}}
	if _, loaded := endpoint.(tun.Port); !loaded {
		t.Fatal("userspace endpoint does not implement tun.Port")
	}
}

func TestUnwrapEndpoint(t *testing.T) {
	base := &Endpoint{}
	for _, endpoint := range []adapter.Endpoint{base, &userspaceEndpoint{Endpoint: base}} {
		unwrapped, loaded := unwrapEndpoint(endpoint)
		if !loaded || unwrapped != base {
			t.Fatalf("unwrapEndpoint(%T) = (%p, %v)", endpoint, unwrapped, loaded)
		}
	}
}

func TestUserspaceEndpointProvidesPacketHandler(t *testing.T) {
	base := &Endpoint{}
	userspace := &userspaceEndpoint{Endpoint: base}
	base.userspaceHandler = userspace
	if base.userspaceHandler != userspace {
		t.Fatal("userspace packet handler was not retained by the base endpoint")
	}
}

func TestSystemInterfaceSelectsPureSystemDataPlane(t *testing.T) {
	endpoint := &Endpoint{
		systemInterface: true,
		server:          &tsnet.Server{},
	}
	endpoint.configureDataPlane()
	if endpoint.server.DataPlaneMode != tsnet.DataPlaneSystem {
		t.Fatalf("DataPlaneMode = %v, want %v", endpoint.server.DataPlaneMode, tsnet.DataPlaneSystem)
	}
}

func TestCloseSystemRouteManagerRetainsFailedCleanup(t *testing.T) {
	sentinel := errors.New("cleanup failed")
	manager := &endpointTestRouteManager{closeErr: sentinel}
	endpoint := &Endpoint{systemRouteManager: manager}
	if err := endpoint.closeSystemRouteManager(); !errors.Is(err, sentinel) {
		t.Fatalf("first close error = %v, want %v", err, sentinel)
	}
	if endpoint.systemRouteManager != manager {
		t.Fatal("failed route cleanup discarded manager before retry")
	}
	if err := endpoint.closeSystemRouteManager(); err != nil {
		t.Fatal(err)
	}
	if endpoint.systemRouteManager != nil {
		t.Fatal("successful retry retained route manager")
	}
	if manager.closeCall != 2 {
		t.Fatalf("close calls = %d, want 2", manager.closeCall)
	}
}

func TestSystemRouteUpdaterLifecycleIsIdempotent(t *testing.T) {
	endpoint := &Endpoint{}
	endpoint.serverStarted.Store(true)
	for i := 0; i < 100; i++ {
		endpoint.startSystemRouteUpdater()
		endpoint.startSystemRouteUpdater()
		for j := 0; j < 8; j++ {
			endpoint.requestSystemRouteUpdate()
		}
		endpoint.stopSystemRouteUpdater()
		if endpoint.systemRouteUpdate != nil || endpoint.systemRouteStop != nil {
			t.Fatal("route updater channels remained after stop")
		}
	}
	endpoint.serverStarted.Store(false)
}

func TestRunSystemRouteUpdaterRetriesAndWakesOnUpdate(t *testing.T) {
	updates := make(chan struct{}, 1)
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopUpdater := func() { stopOnce.Do(func() { close(stop) }) }
	t.Cleanup(stopUpdater)
	attempts := make(chan int, 3)
	done := make(chan struct{})
	var attempt int
	sentinel := errors.New("retry")
	go func() {
		runSystemRouteUpdater(updates, stop, func() error {
			attempt++
			attempts <- attempt
			if attempt < 3 {
				return sentinel
			}
			return nil
		}, time.Hour)
		close(done)
	}()
	updates <- struct{}{}
	waitAttempt := func(want int) {
		t.Helper()
		select {
		case got := <-attempts:
			if got != want {
				t.Fatalf("attempt = %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("attempt %d did not run", want)
		}
	}
	waitAttempt(1)
	// A fresh event must interrupt the long retry timer rather than waiting
	// for the periodic backoff.
	updates <- struct{}{}
	waitAttempt(2)
	updates <- struct{}{}
	waitAttempt(3)
	stopUpdater()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("route updater did not stop after success")
	}
}

func TestRunSystemRouteUpdaterStopsDuringRetry(t *testing.T) {
	updates := make(chan struct{}, 1)
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopUpdater := func() { stopOnce.Do(func() { close(stop) }) }
	t.Cleanup(stopUpdater)
	entered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runSystemRouteUpdater(updates, stop, func() error {
			close(entered)
			return errors.New("retry")
		}, time.Hour)
		close(done)
	}()
	updates <- struct{}{}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("route updater did not start retrying")
	}
	stopUpdater()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("route updater did not stop while waiting for retry")
	}
}

func TestSystemRouteUpdaterConcurrentStartStop(t *testing.T) {
	endpoint := &Endpoint{}
	endpoint.serverStarted.Store(true)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			endpoint.startSystemRouteUpdater()
		}()
		go func() {
			defer wg.Done()
			endpoint.stopSystemRouteUpdater()
		}()
	}
	wg.Wait()
	endpoint.stopSystemRouteUpdater()
	endpoint.serverStarted.Store(false)
	endpoint.systemRouteMu.Lock()
	defer endpoint.systemRouteMu.Unlock()
	if endpoint.systemRouteUpdate != nil || endpoint.systemRouteStop != nil {
		t.Fatal("route updater remained active after concurrent start/stop")
	}
}
