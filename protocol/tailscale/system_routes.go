//go:build with_gvisor

package tailscale

import "net/netip"

// systemRouteManager owns the exit-node default routes for a system-interface
// endpoint.  Tailscale's embedded router deliberately omits those routes so
// that it cannot replace sing-box's primary routing policy.  The manager is
// therefore kept separate from the Tailscale router and only handles the
// interface-scoped defaults needed by sockets explicitly bound to the
// Tailscale system interface.
type systemRouteManager interface {
	Update(enabled bool, ip4, ip6 netip.Addr) error
	Close() error
}
