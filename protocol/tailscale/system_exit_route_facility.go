//go:build with_gvisor

package tailscale

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const (
	systemExitRouteRetryMinDelay = 250 * time.Millisecond
	systemExitRouteRetryMaxDelay = 5 * time.Second
	systemExitRouteCloseAttempts = 4
	systemExitRouteCloseDelay    = 200 * time.Millisecond
	systemExitRouteApplyTimeout  = 15 * time.Second
)

type systemExitRouteSnapshot func() (enabled bool, ip4, ip6 netip.Addr)

// systemExitRouteFacility owns route-worker lifecycle, coalescing, retry,
// readiness generations, cancellation, and ordered cleanup. Platform route
// reconciliation remains behind systemExitRouteReconciler.
type systemExitRouteFacility struct {
	logger     logger.ContextLogger
	reconciler systemExitRouteReconciler
	active     func() bool
	snapshot   systemExitRouteSnapshot

	mu         sync.Mutex
	updates    chan struct{}
	stop       chan struct{}
	wg         sync.WaitGroup
	stopping   bool
	generation uint64
	waiters    map[uint64]chan error
}

func newSystemExitRouteFacility(
	logger logger.ContextLogger,
	reconciler systemExitRouteReconciler,
	active func() bool,
	snapshot systemExitRouteSnapshot,
) *systemExitRouteFacility {
	return &systemExitRouteFacility{
		logger:     logger,
		reconciler: reconciler,
		active:     active,
		snapshot:   snapshot,
		waiters:    make(map[uint64]chan error),
	}
}

// Start moves route socket I/O off Tailscale's reconfigure callback. That
// callback may run under WireGuard internals, so a stalled routing socket must
// never block control-plane convergence.
func (f *systemExitRouteFacility) Start() {
	f.mu.Lock()
	if f.updates != nil || f.stopping || f.reconciler == nil {
		f.mu.Unlock()
		return
	}
	updates := make(chan struct{}, 1)
	stop := make(chan struct{})
	f.updates = updates
	f.stop = stop
	if f.waiters == nil {
		f.waiters = make(map[uint64]chan error)
	}
	f.wg.Add(1)
	f.mu.Unlock()
	go func() {
		defer f.wg.Done()
		runSystemExitRouteUpdater(
			updates,
			stop,
			f.updateResult,
			f.completeGeneration,
			systemExitRouteRetryMinDelay,
			systemExitRouteRetryMaxDelay,
		)
	}()
}

func (f *systemExitRouteFacility) Request() {
	_, _ = f.queue(nil)
}

func (f *systemExitRouteFacility) RequestAndWait(ctx context.Context) error {
	waiter := make(chan error, 1)
	generation, queued := f.queue(waiter)
	if !queued {
		return nil
	}
	select {
	case err := <-waiter:
		return err
	case <-ctx.Done():
		f.mu.Lock()
		if current, loaded := f.waiters[generation]; loaded && current == waiter {
			delete(f.waiters, generation)
		}
		f.mu.Unlock()
		return ctx.Err()
	}
}

func (f *systemExitRouteFacility) Stop() {
	f.mu.Lock()
	stop := f.stop
	if stop == nil || f.stopping {
		f.mu.Unlock()
		return
	}
	f.stopping = true
	close(stop)
	f.mu.Unlock()
	f.wg.Wait()
	f.mu.Lock()
	if f.stop == stop {
		f.stop = nil
		f.updates = nil
	}
	f.stopping = false
	f.mu.Unlock()
	f.failWaiters(net.ErrClosed)
}

func (f *systemExitRouteFacility) Close() error {
	f.Stop()
	var lastErr error
	for attempt := 0; attempt < systemExitRouteCloseAttempts; attempt++ {
		lastErr = f.closeReconciler()
		if lastErr == nil || !isTransientSystemRouteError(lastErr) {
			return lastErr
		}
		if attempt+1 == systemExitRouteCloseAttempts {
			break
		}
		time.Sleep(systemExitRouteCloseDelay)
	}
	return lastErr
}

func (f *systemExitRouteFacility) updateResult() (uint64, time.Duration, error) {
	f.mu.Lock()
	generation := f.generation
	reconciler := f.reconciler
	active := f.active
	snapshot := f.snapshot
	f.mu.Unlock()
	if reconciler == nil || active == nil || !active() || snapshot == nil {
		return generation, 0, nil
	}
	enabled, ip4, ip6 := snapshot()
	retryAfter, err := reconciler.Update(enabled, ip4, ip6)
	if err != nil {
		if f.logger != nil {
			if isTransientSystemRouteError(err) {
				f.logger.Debug("update Tailscale system exit routes: ", err)
			} else {
				f.logger.Warn("update Tailscale system exit routes: ", err)
			}
		}
		return generation, retryAfter, err
	}
	if systemRouteRequiresAddress && enabled && !validSystemRouteAddress(ip4) && !validSystemRouteAddress(ip6) {
		return generation, retryAfter, errSystemRouteAddressPending
	}
	return generation, retryAfter, nil
}

func validSystemRouteAddress(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified()
}

func (f *systemExitRouteFacility) queue(waiter chan error) (uint64, bool) {
	f.mu.Lock()
	updates := f.updates
	if updates == nil || f.active == nil || !f.active() {
		f.mu.Unlock()
		return 0, false
	}
	f.generation++
	generation := f.generation
	if waiter != nil {
		if f.waiters == nil {
			f.waiters = make(map[uint64]chan error)
		}
		f.waiters[generation] = waiter
	}
	f.mu.Unlock()
	select {
	case updates <- struct{}{}:
	default:
	}
	return generation, true
}

func (f *systemExitRouteFacility) completeGeneration(generation uint64, err error) {
	f.mu.Lock()
	for waiterGeneration, waiter := range f.waiters {
		if waiterGeneration > generation {
			continue
		}
		delete(f.waiters, waiterGeneration)
		waiter <- err
	}
	f.mu.Unlock()
}

func (f *systemExitRouteFacility) failWaiters(err error) {
	f.mu.Lock()
	for generation, waiter := range f.waiters {
		delete(f.waiters, generation)
		waiter <- err
	}
	f.mu.Unlock()
}

func (f *systemExitRouteFacility) closeReconciler() error {
	f.mu.Lock()
	reconciler := f.reconciler
	f.mu.Unlock()
	if reconciler == nil {
		return nil
	}
	err := reconciler.Close()
	if err == nil {
		f.mu.Lock()
		if f.reconciler == reconciler {
			f.reconciler = nil
		}
		f.mu.Unlock()
	}
	return err
}

func runSystemExitRouteUpdater(
	updates <-chan struct{},
	stop <-chan struct{},
	update func() (uint64, time.Duration, error),
	complete func(uint64, error),
	retryMinDelay time.Duration,
	retryMaxDelay time.Duration,
) {
	if retryMinDelay <= 0 {
		retryMinDelay = time.Millisecond
	}
	if retryMaxDelay < retryMinDelay {
		retryMaxDelay = retryMinDelay
	}
	for {
		select {
		case _, loaded := <-updates:
			if !loaded {
				return
			}
		case <-stop:
			return
		}
		retryDelay := retryMinDelay
	retryLoop:
		for {
			select {
			case <-stop:
				return
			default:
			}
			generation, deferredDelay, err := update()
			transient := err != nil && isTransientSystemRouteError(err)
			if err == nil {
				complete(generation, nil)
				if deferredDelay <= 0 {
					break retryLoop
				}
				retryDelay = retryMinDelay
			} else if !transient {
				complete(generation, err)
				if deferredDelay <= 0 {
					break retryLoop
				}
				retryDelay = retryMinDelay
			}

			waitDelay := retryDelay
			if deferredDelay > 0 && (err == nil || !transient || deferredDelay < waitDelay) {
				waitDelay = deferredDelay
			}
			timer := time.NewTimer(waitDelay)
			select {
			case _, loaded := <-updates:
				stopSystemExitRouteRetryTimer(timer)
				if !loaded {
					return
				}
				retryDelay = retryMinDelay
				continue
			case <-stop:
				stopSystemExitRouteRetryTimer(timer)
				return
			case <-timer.C:
				if transient && waitDelay == retryDelay && retryDelay < retryMaxDelay {
					retryDelay *= 2
					if retryDelay > retryMaxDelay {
						retryDelay = retryMaxDelay
					}
				}
			}
		}
	}
}

func stopSystemExitRouteRetryTimer(timer *time.Timer) {
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}
