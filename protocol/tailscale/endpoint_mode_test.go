//go:build with_gvisor

package tailscale

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"syscall"
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

func (m *endpointTestRouteManager) Update(bool, netip.Addr, netip.Addr) (time.Duration, error) {
	return 0, nil
}

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

func TestGlobalHookOwnershipRejectsSecondEndpoint(t *testing.T) {
	first := &Endpoint{}
	second := &Endpoint{}
	if err := first.acquireGlobalHooks(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.releaseGlobalHooks)
	if err := second.acquireGlobalHooks(); err == nil {
		second.releaseGlobalHooks()
		t.Fatal("second endpoint unexpectedly acquired process-global Tailscale hooks")
	}
	first.releaseGlobalHooks()
	if err := second.acquireGlobalHooks(); err != nil {
		t.Fatalf("second endpoint could not acquire hooks after release: %v", err)
	}
	second.releaseGlobalHooks()
}

func TestSystemRouteReadinessWaiter(t *testing.T) {
	endpoint := &Endpoint{systemInterface: true, systemRouteUpdate: make(chan struct{}, 1)}
	endpoint.serverStarted.Store(true)
	done := make(chan error, 1)
	go func() {
		done <- endpoint.requestSystemRouteUpdateAndWait(context.Background())
	}()
	select {
	case <-endpoint.systemRouteUpdate:
	case <-time.After(time.Second):
		t.Fatal("route update was not queued")
	}
	endpoint.systemRouteMu.Lock()
	generation := endpoint.systemRouteGeneration
	endpoint.systemRouteMu.Unlock()
	endpoint.completeSystemRouteGeneration(generation, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("route readiness waiter was not completed")
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
	go func() {
		runSystemRouteUpdater(updates, stop, func() (uint64, time.Duration, error) {
			attempt++
			attempts <- attempt
			if attempt < 3 {
				return uint64(attempt), 0, syscall.ENXIO
			}
			return uint64(attempt), 0, nil
		}, func(uint64, error) {}, time.Hour, time.Hour)
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

func TestRunSystemRouteUpdaterStopsOnPermanentError(t *testing.T) {
	updates := make(chan struct{}, 1)
	stop := make(chan struct{})
	completed := make(chan error, 1)
	attempts := 0
	go runSystemRouteUpdater(updates, stop, func() (uint64, time.Duration, error) {
		attempts++
		return 7, 0, syscall.EPERM
	}, func(generation uint64, err error) {
		if generation != 7 {
			t.Errorf("generation = %d, want 7", generation)
		}
		completed <- err
	}, time.Millisecond, 10*time.Millisecond)
	updates <- struct{}{}
	select {
	case err := <-completed:
		if !errors.Is(err, syscall.EPERM) {
			t.Fatalf("completion error = %v, want EPERM", err)
		}
	case <-time.After(time.Second):
		t.Fatal("permanent route error was not reported")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	close(stop)
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
		runSystemRouteUpdater(updates, stop, func() (uint64, time.Duration, error) {
			close(entered)
			return 1, 0, syscall.ENXIO
		}, func(uint64, error) {}, time.Hour, time.Hour)
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
func TestRunSystemRouteUpdaterRunsDeferredReconciliation(t *testing.T) {
	updates := make(chan struct{}, 1)
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopUpdater := func() { stopOnce.Do(func() { close(stop) }) }
	t.Cleanup(stopUpdater)
	attempts := make(chan int, 2)
	completions := make(chan uint64, 2)
	done := make(chan struct{})
	attempt := 0
	go func() {
		runSystemRouteUpdater(updates, stop, func() (uint64, time.Duration, error) {
			attempt++
			attempts <- attempt
			if attempt == 1 {
				return 9, 10 * time.Millisecond, nil
			}
			return 9, 0, nil
		}, func(generation uint64, err error) {
			if err != nil {
				t.Errorf("completion error = %v", err)
			}
			completions <- generation
		}, time.Hour, time.Hour)
		close(done)
	}()
	updates <- struct{}{}
	for want := 1; want <= 2; want++ {
		select {
		case got := <-attempts:
			if got != want {
				t.Fatalf("attempt = %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("deferred attempt %d did not run", want)
		}
	}
	select {
	case generation := <-completions:
		if generation != 9 {
			t.Fatalf("completed generation = %d, want 9", generation)
		}
	case <-time.After(time.Second):
		t.Fatal("successful route generation was not completed before deferred cleanup")
	}
	stopUpdater()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("route updater did not stop")
	}
}

func TestSystemRouteErrorClassificationRequiresAllLeavesTransient(t *testing.T) {
	if !isTransientSystemRouteError(errors.Join(syscall.ENXIO, syscall.EAGAIN)) {
		t.Fatal("all-transient joined error was classified as permanent")
	}
	if isTransientSystemRouteError(errors.Join(syscall.ENETUNREACH, syscall.EPERM)) {
		t.Fatal("permanent EPERM was hidden by a transient sibling")
	}
}
