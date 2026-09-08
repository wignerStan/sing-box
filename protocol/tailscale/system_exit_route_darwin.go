//go:build with_gvisor && darwin

package tailscale

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	systemRouteHandoverGrace   = 5 * time.Second
	systemRouteRequiresAddress = true
)

type systemRouteFamily uint8

const (
	systemRouteIPv4 systemRouteFamily = 4
	systemRouteIPv6 systemRouteFamily = 6
)

type systemRoute struct {
	family  systemRouteFamily
	gateway netip.Addr
	index   int
	mtu     uint32
}

// routeOperationError records whether a routing request reached the kernel.
// Once a complete request has been written, a missing acknowledgement cannot
// prove that the operation did not take effect, so cleanup ownership must be
// retained until a later delete or kernel reply resolves the uncertainty.
type darwinSystemExitRouteReconciler struct {
	name string
	mtu  uint32

	mu           sync.Mutex
	routes       map[systemRouteFamily]systemRoute
	ownedRoutes  map[systemRoute]struct{}
	missingSince map[systemRouteFamily]time.Time
	closing      bool
	closed       bool
	indexes      func() (int, int, error)
	routeOp      func(int, systemRoute) error
	now          func() time.Time
}

func newSystemExitRouteReconciler(name string, mtu uint32, _ string) systemExitRouteReconciler {
	manager := &darwinSystemExitRouteReconciler{
		name:         name,
		mtu:          mtu,
		routes:       make(map[systemRouteFamily]systemRoute),
		ownedRoutes:  make(map[systemRoute]struct{}),
		missingSince: make(map[systemRouteFamily]time.Time),
		now:          time.Now,
	}
	manager.indexes = manager.interfaceIndexes
	manager.routeOp = executeScopedRoute
	return manager
}

// Update installs or removes only the two interface-scoped default routes.
// The route is an interface route (RTAX_GATEWAY=LinkAddr), with the local
// Tailscale address supplied as RTAX_IFA. This is the form macOS accepts for
// an address-less/point-to-point utun, especially for IPv6: using the ULA
// address as an ordinary gateway is rejected as "Network is unreachable".
// A missing address prevents a new route for that family; an existing route is
// retained during convergence. This is important when a network has IPv4 only
// or when Tailscale is still converging.
func (r *darwinSystemExitRouteReconciler) Update(enabled bool, ip4, ip6 netip.Addr) (time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.closing {
		return 0, net.ErrClosed
	}
	if r.routes == nil {
		r.routes = make(map[systemRouteFamily]systemRoute)
	}
	if r.ownedRoutes == nil {
		r.ownedRoutes = make(map[systemRoute]struct{})
	}
	if r.missingSince == nil {
		r.missingSince = make(map[systemRouteFamily]time.Time)
	}
	if r.now == nil {
		r.now = time.Now
	}
	r.rememberCurrentRoutes()

	if !enabled {
		clear(r.missingSince)
		return 0, r.removeAllOwnedRoutes()
	}

	wantIPv4 := ip4.Is4() && !ip4.IsUnspecified()
	wantIPv6 := ip6.Is6() && !ip6.Is4In6() && !ip6.IsUnspecified()
	var if4, if6 int
	if wantIPv4 || wantIPv6 || len(r.routes) > 0 {
		indexes := r.indexes
		if indexes == nil {
			indexes = r.interfaceIndexes
		}
		var err error
		if4, if6, err = indexes()
		if err != nil {
			return 0, fmt.Errorf("Tailscale interface %q index lookup: %w", r.name, err)
		}
		if (wantIPv4 && (if4 <= 0 || if4 > 0xffff)) ||
			(wantIPv6 && (if6 <= 0 || if6 > 0xffff)) {
			return 0, unix.EINVAL
		}
	}

	want := map[systemRouteFamily]systemRoute{}
	if wantIPv4 {
		want[systemRouteIPv4] = systemRoute{family: systemRouteIPv4, gateway: ip4.Unmap(), index: if4, mtu: r.mtu}
	}
	if wantIPv6 {
		want[systemRouteIPv6] = systemRoute{family: systemRouteIPv6, gateway: ip6.Unmap(), index: if6, mtu: r.mtu}
	}
	indexes := map[systemRouteFamily]int{
		systemRouteIPv4: if4,
		systemRouteIPv6: if6,
	}

	var updateErr error
	var nextUpdate time.Duration
	for _, family := range []systemRouteFamily{systemRouteIPv4, systemRouteIPv6} {
		old, hadOld := r.routes[family]
		newRoute, wantsNew := want[family]

		if !wantsNew {
			if !hadOld {
				delete(r.missingSince, family)
				continue
			}
			// Never preserve a route across a utun replacement. A stale
			// scope is worse than a brief missing family because it can
			// blackhole traffic.
			currentIndex := indexes[family]
			if currentIndex > 0 && old.index != currentIndex {
				if err := r.removeOwnedRoute(old); err != nil {
					updateErr = errors.Join(updateErr, scopedRouteError(family, "delete stale", err))
					continue
				}
				delete(r.missingSince, family)
				continue
			}
			missingSince, loaded := r.missingSince[family]
			if !loaded {
				missingSince = r.now()
				r.missingSince[family] = missingSince
			}
			elapsed := r.now().Sub(missingSince)
			if elapsed < 0 {
				elapsed = 0
			}
			if elapsed < systemRouteHandoverGrace {
				remaining := systemRouteHandoverGrace - elapsed
				if nextUpdate == 0 || remaining < nextUpdate {
					nextUpdate = remaining
				}
				continue
			}
			if err := r.removeOwnedRoute(old); err != nil {
				updateErr = errors.Join(updateErr, scopedRouteError(family, "delete expired", err))
				continue
			}
			delete(r.missingSince, family)
			continue
		}

		delete(r.missingSince, family)
		if !hadOld {
			if err := r.install(newRoute); err != nil {
				updateErr = errors.Join(updateErr, scopedRouteError(family, "install", err))
				continue
			}
			r.routes[family] = newRoute
			continue
		}

		if old == newRoute {
			// Re-assert the route because configd or another route writer
			// may have removed or altered the kernel entry without changing
			// our desired state.
			if err := r.apply(unix.RTM_CHANGE, newRoute); err != nil {
				if !isRouteGone(err) {
					updateErr = errors.Join(updateErr, scopedRouteError(family, "change", err))
					continue
				}
				r.forgetOwnedRoute(old)
				delete(r.routes, family)
				if err = r.install(newRoute); err != nil {
					updateErr = errors.Join(updateErr, scopedRouteError(family, "repair", err))
					continue
				}
			} else {
				r.rememberOwnedRoute(newRoute)
			}
			r.routes[family] = newRoute
			continue
		}

		if old.index == newRoute.index {
			// A same-scope address/MTU transition can be changed in place.
			if err := r.apply(unix.RTM_CHANGE, newRoute); err != nil {
				if !isRouteGone(err) {
					if routeOperationMayHaveApplied(err) {
						r.rememberOwnedRoute(newRoute)
					}
					updateErr = errors.Join(updateErr, scopedRouteError(family, "change", err))
					continue
				}
				r.forgetOwnedRoute(old)
				delete(r.routes, family)
				if err = r.install(newRoute); err != nil {
					updateErr = errors.Join(updateErr, scopedRouteError(family, "install replacement", err))
					continue
				}
			} else {
				r.rememberOwnedRoute(newRoute)
			}
			r.forgetOwnedRoute(old)
			r.routes[family] = newRoute
			continue
		}

		// A scope change cannot be performed atomically with RTM_CHANGE.
		// Add the replacement first. Both routes remain in ownedRoutes
		// until old-route deletion and any rollback are definitive.
		if err := r.install(newRoute); err != nil {
			updateErr = errors.Join(updateErr, scopedRouteError(family, "install replacement", err))
			continue
		}
		if err := r.removeOwnedRoute(old); err != nil {
			rollbackErr := r.removeOwnedRoute(newRoute)
			if rollbackErr != nil {
				updateErr = errors.Join(updateErr,
					scopedRouteError(family, "delete old", err),
					scopedRouteError(family, "rollback replacement", rollbackErr))
			} else {
				updateErr = errors.Join(updateErr, scopedRouteError(family, "delete old", err))
			}
			continue
		}
		r.routes[family] = newRoute
	}
	return nextUpdate, updateErr
}

func (r *darwinSystemExitRouteReconciler) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closing = true
	closeErr := r.removeAllOwnedRoutes()
	if closeErr == nil {
		r.closed = true
		clear(r.missingSince)
	}
	return closeErr
}

func (r *darwinSystemExitRouteReconciler) rememberCurrentRoutes() {
	for _, route := range r.routes {
		r.rememberOwnedRoute(route)
	}
}

func (r *darwinSystemExitRouteReconciler) rememberOwnedRoute(route systemRoute) {
	if r.ownedRoutes == nil {
		r.ownedRoutes = make(map[systemRoute]struct{})
	}
	r.ownedRoutes[route] = struct{}{}
}

func (r *darwinSystemExitRouteReconciler) forgetOwnedRoute(route systemRoute) {
	delete(r.ownedRoutes, route)
}

func (r *darwinSystemExitRouteReconciler) removeOwnedRoute(route systemRoute) error {
	err := r.apply(unix.RTM_DELETE, route)
	if err != nil && !isRouteGone(err) {
		return err
	}
	r.forgetOwnedRoute(route)
	if current, loaded := r.routes[route.family]; loaded && current == route {
		delete(r.routes, route.family)
	}
	return nil
}

func (r *darwinSystemExitRouteReconciler) removeAllOwnedRoutes() error {
	r.rememberCurrentRoutes()
	routes := make([]systemRoute, 0, len(r.ownedRoutes))
	for route := range r.ownedRoutes {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].family != routes[j].family {
			return routes[i].family < routes[j].family
		}
		if routes[i].index != routes[j].index {
			return routes[i].index < routes[j].index
		}
		if compared := routes[i].gateway.Compare(routes[j].gateway); compared != 0 {
			return compared < 0
		}
		return routes[i].mtu < routes[j].mtu
	})
	var cleanupErr error
	for _, route := range routes {
		if err := r.removeOwnedRoute(route); err != nil {
			cleanupErr = errors.Join(cleanupErr, scopedRouteError(route.family, "delete", err))
		}
	}
	return cleanupErr
}

func (r *darwinSystemExitRouteReconciler) apply(messageType int, route systemRoute) error {
	if r.routeOp != nil {
		return r.routeOp(messageType, route)
	}
	return executeScopedRoute(messageType, route)
}

func (r *darwinSystemExitRouteReconciler) install(route systemRoute) error {
	err := r.apply(unix.RTM_ADD, route)
	switch {
	case err == nil:
		r.rememberOwnedRoute(route)
		return nil
	case errors.Is(err, unix.EEXIST):
		// The route exists and is adopted only after repairing its MTU
		// and interface address below. Keep cleanup ownership even when
		// that repair returns an error.
		r.rememberOwnedRoute(route)
	default:
		if routeOperationMayHaveApplied(err) {
			r.rememberOwnedRoute(route)
		}
		return err
	}

	err = r.apply(unix.RTM_CHANGE, route)
	if err == nil {
		return nil
	}
	if !isRouteGone(err) {
		return err
	}
	r.forgetOwnedRoute(route)

	// The route disappeared between ADD and CHANGE. Retry the bounded
	// add/change sequence once rather than leaving a gap until another
	// external event.
	err = r.apply(unix.RTM_ADD, route)
	if err == nil {
		r.rememberOwnedRoute(route)
		return nil
	}
	if errors.Is(err, unix.EEXIST) {
		r.rememberOwnedRoute(route)
		err = r.apply(unix.RTM_CHANGE, route)
		if isRouteGone(err) {
			r.forgetOwnedRoute(route)
		}
		return err
	}
	if routeOperationMayHaveApplied(err) {
		r.rememberOwnedRoute(route)
	}
	return err
}

func (r *darwinSystemExitRouteReconciler) interfaceIndexes() (int, int, error) {
	interfaceInfo, err := net.InterfaceByName(r.name)
	if err != nil {
		return 0, 0, fmt.Errorf("%w for %q: %v", errSystemRouteInterfacePending, r.name, err)
	}
	// Both families use the same utun interface index. Keeping the two
	// return values makes the desired route state explicit and leaves room
	// for a future platform with family-specific indexes.
	return interfaceInfo.Index, interfaceInfo.Index, nil
}

func isRouteGone(err error) bool {
	return errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENXIO)
}

func scopedRouteError(family systemRouteFamily, operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("Tailscale %s route %s: %w", systemRouteFamilyName(family), operation, err)
}

func systemRouteFamilyName(family systemRouteFamily) string {
	switch family {
	case systemRouteIPv4:
		return "IPv4"
	case systemRouteIPv6:
		return "IPv6"
	default:
		return fmt.Sprintf("family-%d", family)
	}
}
