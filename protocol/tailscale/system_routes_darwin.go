//go:build with_gvisor && darwin

package tailscale

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var systemRouteMessageSeq atomic.Int32

const (
	scopedRouteReplyTimeout    = time.Second
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

type darwinSystemRouteManager struct {
	name string
	mtu  uint32

	mu           sync.Mutex
	routes       map[systemRouteFamily]systemRoute
	missingSince map[systemRouteFamily]time.Time
	closing      bool
	closed       bool
	indexes      func() (int, int, error)
	routeOp      func(int, systemRoute) error
	now          func() time.Time
}

func newSystemRouteManager(name string, mtu uint32, _ string) systemRouteManager {
	manager := &darwinSystemRouteManager{
		name:         name,
		mtu:          mtu,
		routes:       make(map[systemRouteFamily]systemRoute),
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
func (r *darwinSystemRouteManager) Update(enabled bool, ip4, ip6 netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.closing {
		return net.ErrClosed
	}
	if r.routes == nil {
		r.routes = make(map[systemRouteFamily]systemRoute)
	}
	if r.missingSince == nil {
		r.missingSince = make(map[systemRouteFamily]time.Time)
	}
	if r.now == nil {
		r.now = time.Now
	}

	wantIPv4 := enabled && ip4.Is4() && !ip4.IsUnspecified()
	wantIPv6 := enabled && ip6.Is6() && !ip6.Is4In6() && !ip6.IsUnspecified()
	var if4, if6 int
	if enabled && (wantIPv4 || wantIPv6 || len(r.routes) > 0) {
		indexes := r.indexes
		if indexes == nil {
			indexes = r.interfaceIndexes
		}
		var err error
		if4, if6, err = indexes()
		if err != nil {
			return fmt.Errorf("Tailscale interface %q index lookup: %w", r.name, err)
		}
		if (wantIPv4 && (if4 <= 0 || if4 > 0xffff)) ||
			(wantIPv6 && (if6 <= 0 || if6 > 0xffff)) {
			return unix.EINVAL
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
	for _, family := range []systemRouteFamily{systemRouteIPv4, systemRouteIPv6} {
		old, hadOld := r.routes[family]
		newRoute, wantsNew := want[family]

		if !enabled {
			delete(r.missingSince, family)
			if !hadOld {
				continue
			}
			if err := r.apply(unix.RTM_DELETE, old); err != nil && !isRouteGone(err) {
				updateErr = errors.Join(updateErr, scopedRouteError(family, "delete", err))
				continue
			}
			delete(r.routes, family)
			continue
		}

		if !wantsNew {
			if !hadOld {
				delete(r.missingSince, family)
				continue
			}
			// Never preserve a route across a utun replacement. A stale scope is
			// worse than a brief missing family because it can blackhole traffic.
			currentIndex := indexes[family]
			if currentIndex > 0 && old.index != currentIndex {
				if err := r.apply(unix.RTM_DELETE, old); err != nil && !isRouteGone(err) {
					updateErr = errors.Join(updateErr, scopedRouteError(family, "delete stale", err))
					continue
				}
				delete(r.routes, family)
				delete(r.missingSince, family)
				continue
			}
			missingSince, loaded := r.missingSince[family]
			if !loaded {
				missingSince = r.now()
				r.missingSince[family] = missingSince
			}
			if r.now().Sub(missingSince) < systemRouteHandoverGrace {
				continue
			}
			if err := r.apply(unix.RTM_DELETE, old); err != nil && !isRouteGone(err) {
				updateErr = errors.Join(updateErr, scopedRouteError(family, "delete expired", err))
				continue
			}
			delete(r.routes, family)
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
			// Re-assert the route because configd or another route writer may
			// have removed or altered the kernel entry without changing our
			// desired state.
			if err := r.apply(unix.RTM_CHANGE, newRoute); err != nil {
				if !isRouteGone(err) {
					updateErr = errors.Join(updateErr, scopedRouteError(family, "change", err))
					continue
				}
				if err = r.install(newRoute); err != nil {
					updateErr = errors.Join(updateErr, scopedRouteError(family, "repair", err))
					continue
				}
			}
			r.routes[family] = newRoute
			continue
		}

		if old.index == newRoute.index {
			// A same-scope address/MTU transition can be changed in place, which
			// avoids the delete-first outage of the previous implementation.
			if err := r.apply(unix.RTM_CHANGE, newRoute); err != nil {
				if !isRouteGone(err) {
					updateErr = errors.Join(updateErr, scopedRouteError(family, "change", err))
					continue
				}
				if err = r.install(newRoute); err != nil {
					updateErr = errors.Join(updateErr, scopedRouteError(family, "install replacement", err))
					continue
				}
			}
			r.routes[family] = newRoute
			continue
		}

		// A scope change cannot be performed atomically with RTM_CHANGE. Add the
		// new working route first, then remove the old route. If old-route cleanup
		// fails, roll back the new entry so bookkeeping and kernel state continue
		// to agree on the last known working route.
		if err := r.install(newRoute); err != nil {
			updateErr = errors.Join(updateErr, scopedRouteError(family, "install replacement", err))
			continue
		}
		if err := r.apply(unix.RTM_DELETE, old); err != nil && !isRouteGone(err) {
			rollbackErr := r.apply(unix.RTM_DELETE, newRoute)
			if rollbackErr != nil && !isRouteGone(rollbackErr) {
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
	return updateErr
}

func (r *darwinSystemRouteManager) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closing = true
	var closeErr error
	for _, family := range []systemRouteFamily{systemRouteIPv4, systemRouteIPv6} {
		route, ok := r.routes[family]
		if !ok {
			continue
		}
		if err := r.apply(unix.RTM_DELETE, route); err != nil && !isRouteGone(err) {
			closeErr = errors.Join(closeErr, scopedRouteError(family, "delete", err))
			continue
		}
		delete(r.routes, family)
	}
	if closeErr == nil {
		r.closed = true
	}
	return closeErr
}

func (r *darwinSystemRouteManager) apply(messageType int, route systemRoute) error {
	if r.routeOp != nil {
		return r.routeOp(messageType, route)
	}
	return executeScopedRoute(messageType, route)
}

func (r *darwinSystemRouteManager) install(route systemRoute) error {
	err := r.apply(unix.RTM_ADD, route)
	if !errors.Is(err, unix.EEXIST) {
		return err
	}
	// A route may have survived a previous process or the legacy route
	// supervisor. Change it in place so the MTU metric is corrected instead of
	// blindly adopting a route that still advertises the physical interface's
	// MSS. If the owner removes it between ADD and CHANGE, retry the bounded
	// add/change sequence once rather than leaving a gap until the next event.
	err = r.apply(unix.RTM_CHANGE, route)
	if !isRouteGone(err) {
		return err
	}
	err = r.apply(unix.RTM_ADD, route)
	if errors.Is(err, unix.EEXIST) {
		err = r.apply(unix.RTM_CHANGE, route)
	}
	return err
}

func (r *darwinSystemRouteManager) interfaceIndexes() (int, int, error) {
	interfaceInfo, err := net.InterfaceByName(r.name)
	if err != nil {
		return 0, 0, err
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

// Keep the small operation helpers for package-local callers and older tests;
// the manager uses apply so test doubles can observe the complete lifecycle.
func addScopedDefault(r systemRoute) error {
	return executeScopedRoute(unix.RTM_ADD, r)
}

func deleteScopedDefault(r systemRoute) error {
	return executeScopedRoute(unix.RTM_DELETE, r)
}

func executeScopedRoute(messageType int, r systemRoute) error {
	id := uintptr(os.Getpid())
	seq := int(systemRouteMessageSeq.Add(1))
	request, err := marshalScopedRouteMessage(messageType, r, id, seq)
	if err != nil {
		return err
	}
	socketFD, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socketFD)
	if err = unix.SetsockoptTimeval(socketFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return err
	}
	var n int
	for {
		var writeErr error
		n, writeErr = unix.Write(socketFD, request)
		if errors.Is(writeErr, unix.EINTR) && n == 0 {
			continue
		}
		if writeErr != nil {
			return writeErr
		}
		break
	}
	if n != len(request) {
		// A routing message is atomic. Sending the remainder as a second
		// write would turn it into a malformed independent request.
		return io.ErrShortWrite
	}

	buffer := make([]byte, 4096)
	deadline := time.Now().Add(scopedRouteReplyTimeout)
	for {
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		n, readErr := unix.Read(socketFD, buffer)
		if readErr != nil {
			if errors.Is(readErr, unix.EINTR) {
				continue
			}
			if errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EWOULDBLOCK) {
				if time.Now().After(deadline) {
					return os.ErrDeadlineExceeded
				}
				continue
			}
			return readErr
		}
		if n == 0 {
			if time.Now().After(deadline) {
				return os.ErrDeadlineExceeded
			}
			continue
		}
		messages, parseErr := route.ParseRIB(route.RIBTypeRoute, buffer[:n])
		if parseErr != nil {
			if time.Now().After(deadline) {
				return parseErr
			}
			continue
		}
		for _, rawMessage := range messages {
			reply, ok := rawMessage.(*route.RouteMessage)
			if !ok || reply.ID != id || reply.Seq != seq {
				continue
			}
			return reply.Err
		}
		if time.Now().After(deadline) {
			return os.ErrDeadlineExceeded
		}
	}
}

func scopedRouteMessage(messageType int, r systemRoute, id uintptr, seq int) (route.RouteMessage, error) {
	if messageType != unix.RTM_ADD && messageType != unix.RTM_DELETE && messageType != unix.RTM_CHANGE {
		return route.RouteMessage{}, unix.EINVAL
	}
	if r.index <= 0 || r.index > 0xffff {
		return route.RouteMessage{}, unix.EINVAL
	}
	if !r.gateway.IsValid() || r.gateway.IsUnspecified() || r.gateway.Zone() != "" {
		return route.RouteMessage{}, unix.EINVAL
	}
	var destination, mask, interfaceAddress route.Addr
	switch r.family {
	case systemRouteIPv4:
		if !r.gateway.Is4() {
			return route.RouteMessage{}, unix.EAFNOSUPPORT
		}
		destination = &route.Inet4Addr{}
		mask = &route.Inet4Addr{}
		interfaceAddress = &route.Inet4Addr{IP: r.gateway.As4()}
	case systemRouteIPv6:
		if !r.gateway.Is6() || r.gateway.Is4In6() {
			return route.RouteMessage{}, unix.EAFNOSUPPORT
		}
		destination = &route.Inet6Addr{}
		mask = &route.Inet6Addr{}
		interfaceAddress = &route.Inet6Addr{IP: r.gateway.As16()}
	default:
		return route.RouteMessage{}, unix.EAFNOSUPPORT
	}

	flags := unix.RTF_STATIC | unix.RTF_IFSCOPE
	if messageType == unix.RTM_ADD || messageType == unix.RTM_CHANGE {
		flags |= unix.RTF_UP
	}
	return route.RouteMessage{
		Type:    messageType,
		Version: unix.RTM_VERSION,
		Flags:   flags,
		Index:   r.index,
		ID:      id,
		Seq:     seq,
		Addrs: []route.Addr{
			syscall.RTAX_DST:     destination,
			syscall.RTAX_GATEWAY: &route.LinkAddr{Index: r.index},
			syscall.RTAX_NETMASK: mask,
			syscall.RTAX_IFA:     interfaceAddress,
		},
	}, nil
}

// Darwin's rt_msghdr stores rtm_inits before rt_metrics. x/net/route
// intentionally exposes metrics only for decoding, so set these fields after
// its portable address marshaller has produced the request. Derive the offsets
// from x/sys' generated Darwin ABI types instead of duplicating architecture-
// specific constants. Locking the MTU is deliberate: the interface MTU is a
// hard utun boundary, and allowing TCP's route cache to replace it with the
// physical interface MTU recreates the oversized-segment failure this manager
// exists to prevent. RTM_DELETE leaves metrics unset so route identity is
// determined solely by the destination/scope.
const (
	darwinRouteInitsOffset = int(unsafe.Offsetof(unix.RtMsghdr{}.Inits))
	darwinRouteLocksOffset = int(unsafe.Offsetof(unix.RtMsghdr{}.Rmx)) + int(unsafe.Offsetof(unix.RtMetrics{}.Locks))
	darwinRouteMTUOffset   = int(unsafe.Offsetof(unix.RtMsghdr{}.Rmx)) + int(unsafe.Offsetof(unix.RtMetrics{}.Mtu))
)

func marshalScopedRouteMessage(messageType int, r systemRoute, id uintptr, seq int) ([]byte, error) {
	message, err := scopedRouteMessage(messageType, r, id, seq)
	if err != nil {
		return nil, err
	}
	request, err := message.Marshal()
	if err != nil {
		return nil, err
	}
	if r.mtu == 0 || (messageType != unix.RTM_ADD && messageType != unix.RTM_CHANGE) {
		return request, nil
	}
	if len(request) < darwinRouteMTUOffset+4 {
		return nil, io.ErrUnexpectedEOF
	}
	binary.LittleEndian.PutUint32(request[darwinRouteInitsOffset:darwinRouteInitsOffset+4], unix.RTV_MTU)
	binary.LittleEndian.PutUint32(request[darwinRouteLocksOffset:darwinRouteLocksOffset+4], unix.RTV_MTU)
	binary.LittleEndian.PutUint32(request[darwinRouteMTUOffset:darwinRouteMTUOffset+4], r.mtu)
	return request, nil
}
