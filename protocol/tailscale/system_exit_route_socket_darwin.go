//go:build with_gvisor && darwin

package tailscale

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var systemRouteMessageSeq atomic.Int32

const scopedRouteReplyTimeout = time.Second

type routeOperationError struct {
	err            error
	mayHaveApplied bool
}

func (e *routeOperationError) Error() string { return e.err.Error() }
func (e *routeOperationError) Unwrap() error { return e.err }

func newRouteOperationError(err error, mayHaveApplied bool) error {
	if err == nil {
		return nil
	}
	return &routeOperationError{err: err, mayHaveApplied: mayHaveApplied}
}

func routeOperationMayHaveApplied(err error) bool {
	if err == nil {
		return false
	}
	var operationError *routeOperationError
	if errors.As(err, &operationError) {
		return operationError.mayHaveApplied
	}
	// Test doubles and third-party route operators cannot communicate the
	// operation phase, so conservatively retain ownership for unknown errors.
	return true
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
		return newRouteOperationError(err, false)
	}
	socketFD, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return newRouteOperationError(err, false)
	}
	defer unix.Close(socketFD)
	if err = unix.SetsockoptTimeval(socketFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return newRouteOperationError(err, false)
	}
	var n int
	for {
		var writeErr error
		n, writeErr = unix.Write(socketFD, request)
		if errors.Is(writeErr, unix.EINTR) && n == 0 {
			continue
		}
		if writeErr != nil {
			return newRouteOperationError(writeErr, n > 0)
		}
		break
	}
	if n != len(request) {
		// A routing message is atomic. Sending the remainder as a second
		// write would turn it into a malformed independent request.
		return newRouteOperationError(io.ErrShortWrite, n > 0)
	}

	buffer := make([]byte, 4096)
	deadline := time.Now().Add(scopedRouteReplyTimeout)
	for {
		if !time.Now().Before(deadline) {
			return newRouteOperationError(os.ErrDeadlineExceeded, true)
		}
		n, readErr := unix.Read(socketFD, buffer)
		if readErr != nil {
			if errors.Is(readErr, unix.EINTR) {
				continue
			}
			if errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EWOULDBLOCK) {
				if time.Now().After(deadline) {
					return newRouteOperationError(os.ErrDeadlineExceeded, true)
				}
				continue
			}
			return newRouteOperationError(readErr, true)
		}
		if n == 0 {
			if time.Now().After(deadline) {
				return newRouteOperationError(os.ErrDeadlineExceeded, true)
			}
			continue
		}
		messages, parseErr := route.ParseRIB(route.RIBTypeRoute, buffer[:n])
		if parseErr != nil {
			if time.Now().After(deadline) {
				return newRouteOperationError(parseErr, true)
			}
			continue
		}
		for _, rawMessage := range messages {
			reply, ok := rawMessage.(*route.RouteMessage)
			if !ok || reply.ID != id || reply.Seq != seq {
				continue
			}
			return newRouteOperationError(reply.Err, false)
		}
		if time.Now().After(deadline) {
			return newRouteOperationError(os.ErrDeadlineExceeded, true)
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
