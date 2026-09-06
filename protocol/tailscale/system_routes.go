//go:build with_gvisor

package tailscale

import (
	"errors"
	"net/netip"
	"os"
	"syscall"
	"time"
)

var (
	errSystemRouteAddressPending   = errors.New("Tailscale address is not ready for system exit route")
	errSystemRouteInterfacePending = errors.New("Tailscale system interface is not ready")
)

// systemRouteManager owns the exit-node default routes for a system-interface
// endpoint. Tailscale's embedded router deliberately omits those routes so
// that it cannot replace sing-box's primary routing policy. The manager is
// therefore kept separate from the Tailscale router and only handles the
// interface-scoped defaults needed by sockets explicitly bound to the
// Tailscale system interface.
type systemRouteManager interface {
	// Update returns the delay before a deferred reconciliation is required.
	// A positive delay is independent from readiness: currently usable routes
	// may already be installed while an old address-family route is retained
	// for its bounded handover grace period.
	Update(enabled bool, ip4, ip6 netip.Addr) (time.Duration, error)
	Close() error
}

// systemExitNodeEnabled reads the committed Tailscale preference instead of
// an asynchronously published cache. This makes preference commit and route
// readiness part of one ordered state transition: an older watcher snapshot
// cannot overwrite a newer SetTailscaleExitNode decision.
func (t *Endpoint) systemExitNodeEnabled() bool {
	localBackend := t.localBackend
	if localBackend == nil {
		return false
	}
	prefs := localBackend.Prefs()
	return prefs.ExitNodeID() != "" || prefs.ExitNodeIP().IsValid() || prefs.AutoExitNode().IsSet()
}

// isTransientSystemRouteError returns true only when every leaf error is
// retryable. errors.Join is used for multi-family reconciliation, and one
// transient sibling must not hide a permanent failure such as EPERM.
func isTransientSystemRouteError(err error) bool {
	if err == nil {
		return false
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		children := wrapped.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !isTransientSystemRouteError(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		if child := wrapped.Unwrap(); child != nil {
			return isTransientSystemRouteError(child)
		}
	}
	return errors.Is(err, errSystemRouteAddressPending) ||
		errors.Is(err, errSystemRouteInterfacePending) ||
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
