//go:build with_gvisor && !darwin

package tailscale

import "net/netip"

// System-interface route ownership is currently implemented for Darwin,
// where the endpoint's utun must use an interface-scoped route.  Other
// platforms retain the router behavior supplied by their native Tailscale
// integration; this no-op keeps the endpoint buildable there.
type unsupportedSystemRouteManager struct{}

func newSystemRouteManager(_ string, _ ...uint32) systemRouteManager {
	return unsupportedSystemRouteManager{}
}

func (unsupportedSystemRouteManager) Update(bool, netip.Addr, netip.Addr) error { return nil }

func (unsupportedSystemRouteManager) Close() error { return nil }
