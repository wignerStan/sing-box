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
)

type endpointTestRouteReconciler struct {
	mu        sync.Mutex
	closeErr  error
	closeCall int
}

func (m *endpointTestRouteReconciler) Update(bool, netip.Addr, netip.Addr) (time.Duration, error) {
	return 0, nil
}

func (m *endpointTestRouteReconciler) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCall++
	err := m.closeErr
	m.closeErr = nil
	return err
}

func TestSystemExitRouteReadinessWaiter(t *testing.T) {
	facility := &systemExitRouteFacility{
		active:  func() bool { return true },
		updates: make(chan struct{}, 1),
		waiters: make(map[uint64]chan error),
	}
	done := make(chan error, 1)
	go func() {
		done <- facility.RequestAndWait(context.Background())
	}()
	select {
	case <-facility.updates:
	case <-time.After(time.Second):
		t.Fatal("route update was not queued")
	}
	facility.mu.Lock()
	generation := facility.generation
	facility.mu.Unlock()
	facility.completeGeneration(generation, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("route readiness waiter was not completed")
	}
}

func TestCloseSystemExitRouteReconcilerRetainsFailedCleanup(t *testing.T) {
	sentinel := errors.New("cleanup failed")
	reconciler := &endpointTestRouteReconciler{closeErr: sentinel}
	facility := &systemExitRouteFacility{reconciler: reconciler}
	if err := facility.closeReconciler(); !errors.Is(err, sentinel) {
		t.Fatalf("first close error = %v, want %v", err, sentinel)
	}
	if facility.reconciler != reconciler {
		t.Fatal("failed route cleanup discarded reconciler before retry")
	}
	if err := facility.closeReconciler(); err != nil {
		t.Fatal(err)
	}
	if facility.reconciler != nil {
		t.Fatal("successful retry retained route reconciler")
	}
	if reconciler.closeCall != 2 {
		t.Fatalf("close calls = %d, want 2", reconciler.closeCall)
	}
}

func TestSystemExitRouteFacilityLifecycleIsIdempotent(t *testing.T) {
	facility := newSystemExitRouteFacility(
		nil,
		&endpointTestRouteReconciler{},
		func() bool { return true },
		func() (bool, netip.Addr, netip.Addr) { return false, netip.Addr{}, netip.Addr{} },
	)
	for i := 0; i < 100; i++ {
		facility.Start()
		facility.Start()
		for j := 0; j < 8; j++ {
			facility.Request()
		}
		facility.Stop()
		facility.mu.Lock()
		active := facility.updates != nil || facility.stop != nil
		facility.mu.Unlock()
		if active {
			t.Fatal("route facility channels remained after stop")
		}
	}
}

func TestRunSystemExitRouteUpdaterRetriesAndWakesOnUpdate(t *testing.T) {
	updates := make(chan struct{}, 1)
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopUpdater := func() { stopOnce.Do(func() { close(stop) }) }
	t.Cleanup(stopUpdater)
	attempts := make(chan int, 3)
	done := make(chan struct{})
	var attempt int
	go func() {
		runSystemExitRouteUpdater(updates, stop, func() (uint64, time.Duration, error) {
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

func TestRunSystemExitRouteUpdaterStopsOnPermanentError(t *testing.T) {
	updates := make(chan struct{}, 1)
	stop := make(chan struct{})
	completed := make(chan error, 1)
	attempts := 0
	go runSystemExitRouteUpdater(updates, stop, func() (uint64, time.Duration, error) {
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

func TestRunSystemExitRouteUpdaterStopsDuringRetry(t *testing.T) {
	updates := make(chan struct{}, 1)
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopUpdater := func() { stopOnce.Do(func() { close(stop) }) }
	t.Cleanup(stopUpdater)
	entered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runSystemExitRouteUpdater(updates, stop, func() (uint64, time.Duration, error) {
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

func TestSystemExitRouteFacilityConcurrentStartStop(t *testing.T) {
	facility := newSystemExitRouteFacility(
		nil,
		&endpointTestRouteReconciler{},
		func() bool { return true },
		func() (bool, netip.Addr, netip.Addr) { return false, netip.Addr{}, netip.Addr{} },
	)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			facility.Start()
		}()
		go func() {
			defer wg.Done()
			facility.Stop()
		}()
	}
	wg.Wait()
	facility.Stop()
	facility.mu.Lock()
	defer facility.mu.Unlock()
	if facility.updates != nil || facility.stop != nil {
		t.Fatal("route facility remained active after concurrent start/stop")
	}
}

func TestRunSystemExitRouteUpdaterRunsDeferredReconciliation(t *testing.T) {
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
		runSystemExitRouteUpdater(updates, stop, func() (uint64, time.Duration, error) {
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

func TestSystemExitRouteErrorClassificationRequiresAllLeavesTransient(t *testing.T) {
	if !isTransientSystemRouteError(errors.Join(syscall.ENXIO, syscall.EAGAIN)) {
		t.Fatal("all-transient joined error was classified as permanent")
	}
	if isTransientSystemRouteError(errors.Join(syscall.ENETUNREACH, syscall.EPERM)) {
		t.Fatal("permanent EPERM was hidden by a transient sibling")
	}
}
