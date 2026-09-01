//go:build with_gvisor

package tailscale

import (
	"errors"
	"net/netip"
	"os"
	"syscall"
)

var errSystemRouteAddressPending = errors.New("Tailscale address is not ready for system exit route")

// systemRouteManager owns the exit-node default routes for a system-interface
// endpoint. Tailscale's embedded router deliberately omits those routes so
// that it cannot replace sing-box's primary routing policy. The manager is
// therefore kept separate from the Tailscale router and only handles the
// interface-scoped defaults needed by sockets explicitly bound to the
// Tailscale system interface.
type systemRouteManager interface {
	Update(enabled bool, ip4, ip6 netip.Addr) error
	Close() error
}

func isTransientSystemRouteError(err error) bool {
	return errors.Is(err, errSystemRouteAddressPending) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.ENXIO) ||
		errors.Is(err, syscall.ESRCH) ||
		errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, syscall.ENETUNREACH)
}
