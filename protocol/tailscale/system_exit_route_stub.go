//go:build with_gvisor && !darwin

package tailscale

import (
	"net/netip"
	"time"
)

const systemRouteRequiresAddress = false

// System-interface route ownership is currently implemented for Darwin,
// where the endpoint's utun must use an interface-scoped route. Other
// platforms retain the router behavior supplied by their native Tailscale
// integration; this no-op keeps the endpoint buildable there.
type unsupportedSystemExitRouteReconciler struct{}

func newSystemExitRouteReconciler(_ string, _ uint32, _ string) systemExitRouteReconciler {
	return unsupportedSystemExitRouteReconciler{}
}

func (unsupportedSystemExitRouteReconciler) Update(bool, netip.Addr, netip.Addr) (time.Duration, error) {
	return 0, nil
}

func (unsupportedSystemExitRouteReconciler) Close() error { return nil }
