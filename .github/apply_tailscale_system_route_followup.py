from pathlib import Path
import re
import textwrap


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old[:100]!r}")
    path.write_text(text.replace(old, new, 1))


def replace_region(path: Path, start: str, end: str, replacement: str) -> None:
    text = path.read_text()
    start_index = text.find(start)
    if start_index < 0:
        raise SystemExit(f"{path}: missing region start {start!r}")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise SystemExit(f"{path}: missing region end {end!r}")
    path.write_text(text[:start_index] + replacement + text[end_index:])


def go_source(source: str) -> str:
    return textwrap.dedent(source).lstrip()


system_routes = Path("protocol/tailscale/system_routes.go")
system_routes.write_text(go_source(r'''
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
'''))

system_routes_stub = Path("protocol/tailscale/system_routes_stub.go")
system_routes_stub.write_text(go_source(r'''
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
    type unsupportedSystemRouteManager struct{}

    func newSystemRouteManager(_ string, _ uint32, _ string) systemRouteManager {
        return unsupportedSystemRouteManager{}
    }

    func (unsupportedSystemRouteManager) Update(bool, netip.Addr, netip.Addr) (time.Duration, error) {
        return 0, nil
    }

    func (unsupportedSystemRouteManager) Close() error { return nil }
'''))

endpoint = Path("protocol/tailscale/endpoint.go")
replace_once(endpoint, "\texitNodeActive        atomic.Bool\n", "")
replace_once(endpoint, "\ttailscaleEndpoint.exitNodeActive.Store(false)\n", "")
replace_once(
    endpoint,
    '''\t\t\tstatus := localBackend.StatusWithoutPeers()
\t\t\tprefs := localBackend.Prefs()
\t\t\tt.exitNodeActive.Store(prefs.ExitNodeID() != "" || prefs.ExitNodeIP().IsValid() || prefs.AutoExitNode().IsSet())
\t\t\tt.requestSystemRouteUpdate()
''',
    '''\t\t\tstatus := localBackend.StatusWithoutPeers()
\t\t\tt.requestSystemRouteUpdate()
''',
)
for line in (
    '\tt.exitNodeActive.Store(t.exitNode != "")\n',
    '\tt.exitNodeActive.Store(stableID != "")\n',
    '\tt.exitNodeActive.Store(false)\n',
):
    replace_once(endpoint, line, "")
replace_once(
    endpoint,
    '''\t\tt.systemTunDevice = wgTunDevice
\t\tt.systemDialer = systemDialer
\t\tt.systemRouteMu.Lock()
''',
    '''\t\tt.systemTunDevice = wgTunDevice
\t\tt.systemDialer = systemDialer
\t\tt.server.DataPlaneDial = func(ctx context.Context, network, address string) (net.Conn, error) {
\t\t\treturn systemDialer.DialContext(ctx, network, M.ParseSocksaddr(address))
\t\t}
\t\tt.systemRouteMu.Lock()
''',
)
replace_region(
    endpoint,
    "func (t *Endpoint) updateSystemRoutes() {",
    "func validSystemRouteAddress",
    go_source(r'''
        func (t *Endpoint) updateSystemRoutes() {
            _, _, _ = t.updateSystemRoutesResult()
        }

        func (t *Endpoint) updateSystemRoutesResult() (uint64, time.Duration, error) {
            t.systemRouteMu.Lock()
            generation := t.systemRouteGeneration
            manager := t.systemRouteManager
            t.systemRouteMu.Unlock()
            if manager == nil || t.server == nil || !t.serverStarted.Load() {
                return generation, 0, nil
            }
            ip4, ip6 := t.server.TailscaleIPs()
            enabled := t.systemExitNodeEnabled()
            retryAfter, err := manager.Update(enabled, ip4, ip6)
            if err != nil {
                if isTransientSystemRouteError(err) {
                    t.logger.Debug("update Tailscale system exit routes: ", err)
                } else {
                    t.logger.Warn("update Tailscale system exit routes: ", err)
                }
                return generation, retryAfter, err
            }
            if systemRouteRequiresAddress && enabled && !validSystemRouteAddress(ip4) && !validSystemRouteAddress(ip6) {
                return generation, retryAfter, errSystemRouteAddressPending
            }
            return generation, retryAfter, nil
        }

    '''),
)
replace_region(
    endpoint,
    "func runSystemRouteUpdater(",
    "func stopSystemRouteRetryTimer",
    go_source(r'''
        func runSystemRouteUpdater(
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
                        stopSystemRouteRetryTimer(timer)
                        if !loaded {
                            return
                        }
                        retryDelay = retryMinDelay
                        continue
                    case <-stop:
                        stopSystemRouteRetryTimer(timer)
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

    '''),
)

darwin = Path("protocol/tailscale/system_routes_darwin.go")
replace_once(darwin, '\t"os"\n\t"sync"\n', '\t"os"\n\t"sort"\n\t"sync"\n')
replace_once(
    darwin,
    '''type systemRoute struct {
\tfamily  systemRouteFamily
\tgateway netip.Addr
\tindex   int
\tmtu     uint32
}

''',
    '''type systemRoute struct {
\tfamily  systemRouteFamily
\tgateway netip.Addr
\tindex   int
\tmtu     uint32
}

// routeOperationError records whether a routing request reached the kernel.
// Once a complete request has been written, a missing acknowledgement cannot
// prove that the operation did not take effect, so cleanup ownership must be
// retained until a later delete or kernel reply resolves the uncertainty.
type routeOperationError struct {
\terr            error
\tmayHaveApplied bool
}

func (e *routeOperationError) Error() string { return e.err.Error() }
func (e *routeOperationError) Unwrap() error { return e.err }

func newRouteOperationError(err error, mayHaveApplied bool) error {
\tif err == nil {
\t\treturn nil
\t}
\treturn &routeOperationError{err: err, mayHaveApplied: mayHaveApplied}
}

func routeOperationMayHaveApplied(err error) bool {
\tif err == nil {
\t\treturn false
\t}
\tvar operationError *routeOperationError
\tif errors.As(err, &operationError) {
\t\treturn operationError.mayHaveApplied
\t}
\t// Test doubles and third-party route operators cannot communicate the
\t// operation phase, so conservatively retain ownership for unknown errors.
\treturn true
}

''',
)
replace_once(
    darwin,
    '''\tmu           sync.Mutex
\troutes       map[systemRouteFamily]systemRoute
\tmissingSince map[systemRouteFamily]time.Time
''',
    '''\tmu           sync.Mutex
\troutes       map[systemRouteFamily]systemRoute
\townedRoutes  map[systemRoute]struct{}
\tmissingSince map[systemRouteFamily]time.Time
''',
)
replace_once(
    darwin,
    '''\t\troutes:       make(map[systemRouteFamily]systemRoute),
\t\tmissingSince: make(map[systemRouteFamily]time.Time),
''',
    '''\t\troutes:       make(map[systemRouteFamily]systemRoute),
\t\townedRoutes:  make(map[systemRoute]struct{}),
\t\tmissingSince: make(map[systemRouteFamily]time.Time),
''',
)
replace_region(
    darwin,
    "func (r *darwinSystemRouteManager) Update(",
    "func (r *darwinSystemRouteManager) Close",
    go_source(r'''
        func (r *darwinSystemRouteManager) Update(enabled bool, ip4, ip6 netip.Addr) (time.Duration, error) {
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

    '''),
)
replace_region(
    darwin,
    "func (r *darwinSystemRouteManager) Close",
    "func (r *darwinSystemRouteManager) apply",
    go_source(r'''
        func (r *darwinSystemRouteManager) Close() error {
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

        func (r *darwinSystemRouteManager) rememberCurrentRoutes() {
            for _, route := range r.routes {
                r.rememberOwnedRoute(route)
            }
        }

        func (r *darwinSystemRouteManager) rememberOwnedRoute(route systemRoute) {
            if r.ownedRoutes == nil {
                r.ownedRoutes = make(map[systemRoute]struct{})
            }
            r.ownedRoutes[route] = struct{}{}
        }

        func (r *darwinSystemRouteManager) forgetOwnedRoute(route systemRoute) {
            delete(r.ownedRoutes, route)
        }

        func (r *darwinSystemRouteManager) removeOwnedRoute(route systemRoute) error {
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

        func (r *darwinSystemRouteManager) removeAllOwnedRoutes() error {
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

    '''),
)
replace_region(
    darwin,
    "func (r *darwinSystemRouteManager) install",
    "func (r *darwinSystemRouteManager) interfaceIndexes",
    go_source(r'''
        func (r *darwinSystemRouteManager) install(route systemRoute) error {
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

    '''),
)
replace_once(
    darwin,
    '''\tinterfaceInfo, err := net.InterfaceByName(r.name)
\tif err != nil {
\t\treturn 0, 0, err
\t}
''',
    '''\tinterfaceInfo, err := net.InterfaceByName(r.name)
\tif err != nil {
\t\treturn 0, 0, fmt.Errorf("%w for %q: %v", errSystemRouteInterfacePending, r.name, err)
\t}
''',
)
replace_region(
    darwin,
    "func executeScopedRoute(",
    "func scopedRouteMessage",
    go_source(r'''
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

    '''),
)

endpoint_tests = Path("protocol/tailscale/endpoint_mode_test.go")
replace_once(
    endpoint_tests,
    "func (m *endpointTestRouteManager) Update(bool, netip.Addr, netip.Addr) error { return nil }",
    "func (m *endpointTestRouteManager) Update(bool, netip.Addr, netip.Addr) (time.Duration, error) { return 0, nil }",
)
endpoint_test_text = endpoint_tests.read_text()
endpoint_test_text = endpoint_test_text.replace("func() (uint64, error)", "func() (uint64, time.Duration, error)")
for old, new in (
    ("return uint64(attempt), syscall.ENXIO", "return uint64(attempt), 0, syscall.ENXIO"),
    ("return uint64(attempt), nil", "return uint64(attempt), 0, nil"),
    ("return 7, syscall.EPERM", "return 7, 0, syscall.EPERM"),
    ("return 1, syscall.ENXIO", "return 1, 0, syscall.ENXIO"),
):
    if old not in endpoint_test_text:
        raise SystemExit(f"{endpoint_tests}: missing expected callback return {old!r}")
    endpoint_test_text = endpoint_test_text.replace(old, new)
endpoint_test_text += go_source(r'''

    func TestRunSystemRouteUpdaterRunsDeferredReconciliation(t *testing.T) {
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
            runSystemRouteUpdater(updates, stop, func() (uint64, time.Duration, error) {
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

    func TestSystemRouteErrorClassificationRequiresAllLeavesTransient(t *testing.T) {
        if !isTransientSystemRouteError(errors.Join(syscall.ENXIO, syscall.EAGAIN)) {
            t.Fatal("all-transient joined error was classified as permanent")
        }
        if isTransientSystemRouteError(errors.Join(syscall.ENETUNREACH, syscall.EPERM)) {
            t.Fatal("permanent EPERM was hidden by a transient sibling")
        }
    }
''')
endpoint_tests.write_text(endpoint_test_text)

darwin_tests = Path("protocol/tailscale/system_routes_darwin_test.go")
replace_once(
    darwin_tests,
    '''\t\troutes:       make(map[systemRouteFamily]systemRoute),
\t\tmissingSince: make(map[systemRouteFamily]time.Time),
''',
    '''\t\troutes:       make(map[systemRouteFamily]systemRoute),
\t\townedRoutes:  make(map[systemRoute]struct{}),
\t\tmissingSince: make(map[systemRouteFamily]time.Time),
''',
)
darwin_test_text = darwin_tests.read_text()
darwin_test_text = darwin_test_text.replace("if err := manager.Update(", "if _, err := manager.Update(")
darwin_test_text = re.sub(r"(?m)^(\s*)err := manager\.Update\(", r"\1_, err := manager.Update(", darwin_test_text)
if re.search(r"(?m)(?:if\s+)?err := manager\.Update\(", darwin_test_text):
    raise SystemExit(f"{darwin_tests}: unconverted Update assignment remains")
darwin_test_text += go_source(r'''

    func TestSystemRouteManagerReturnsMissingFamilyDeadline(t *testing.T) {
        ip4 := netip.MustParseAddr("100.71.1.1")
        ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
        now := time.Unix(100, 0)
        manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(int, systemRoute) error { return nil })
        manager.now = func() time.Time { return now }
        if _, err := manager.Update(true, ip4, ip6); err != nil {
            t.Fatal(err)
        }
        retryAfter, err := manager.Update(true, ip4, netip.Addr{})
        if err != nil {
            t.Fatal(err)
        }
        if retryAfter <= 0 || retryAfter > systemRouteHandoverGrace {
            t.Fatalf("retryAfter = %v, want a bounded handover deadline", retryAfter)
        }
        now = now.Add(retryAfter + time.Millisecond)
        retryAfter, err = manager.Update(true, ip4, netip.Addr{})
        if err != nil {
            t.Fatal(err)
        }
        if retryAfter != 0 {
            t.Fatalf("retryAfter after expiry = %v, want 0", retryAfter)
        }
        if _, loaded := manager.routes[systemRouteIPv6]; loaded {
            t.Fatal("IPv6 route survived its scheduled handover expiry")
        }
    }

    func TestSystemRouteManagerCleansUncertainInstall(t *testing.T) {
        ip4 := netip.MustParseAddr("100.71.1.1")
        kernelRoutes := make(map[systemRoute]bool)
        acknowledgementLost := true
        sentinel := errors.New("route acknowledgement lost")
        manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, route systemRoute) error {
            switch typ {
            case unix.RTM_ADD:
                kernelRoutes[route] = true
                if acknowledgementLost {
                    acknowledgementLost = false
                    return sentinel
                }
            case unix.RTM_DELETE:
                delete(kernelRoutes, route)
            }
            return nil
        })
        if _, err := manager.Update(true, ip4, netip.Addr{}); !errors.Is(err, sentinel) {
            t.Fatalf("install error = %v, want %v", err, sentinel)
        }
        if len(manager.routes) != 0 || len(manager.ownedRoutes) != 1 {
            t.Fatalf("state after uncertain install: routes=%#v owned=%#v", manager.routes, manager.ownedRoutes)
        }
        if _, err := manager.Update(false, netip.Addr{}, netip.Addr{}); err != nil {
            t.Fatal(err)
        }
        if len(kernelRoutes) != 0 || len(manager.ownedRoutes) != 0 {
            t.Fatalf("uncertain route escaped cleanup: kernel=%#v owned=%#v", kernelRoutes, manager.ownedRoutes)
        }
    }

    func TestSystemRouteManagerRetainsBothRoutesAfterFailedRollback(t *testing.T) {
        oldIP := netip.MustParseAddr("100.71.1.1")
        newIP := netip.MustParseAddr("100.72.2.2")
        index := 17
        kernelRoutes := make(map[systemRoute]bool)
        failDeletes := true
        sentinel := errors.New("delete failed")
        manager := newFakeSystemRouteManager(func() (int, int, error) { return index, index, nil }, func(typ int, route systemRoute) error {
            switch typ {
            case unix.RTM_ADD, unix.RTM_CHANGE:
                kernelRoutes[route] = true
            case unix.RTM_DELETE:
                if failDeletes {
                    return sentinel
                }
                delete(kernelRoutes, route)
            }
            return nil
        })
        if _, err := manager.Update(true, oldIP, netip.Addr{}); err != nil {
            t.Fatal(err)
        }
        index = 19
        if _, err := manager.Update(true, newIP, netip.Addr{}); !errors.Is(err, sentinel) {
            t.Fatalf("replacement error = %v, want %v", err, sentinel)
        }
        if len(kernelRoutes) != 2 || len(manager.ownedRoutes) != 2 {
            t.Fatalf("failed rollback ownership: kernel=%#v owned=%#v", kernelRoutes, manager.ownedRoutes)
        }
        failDeletes = false
        if _, err := manager.Update(false, netip.Addr{}, netip.Addr{}); err != nil {
            t.Fatal(err)
        }
        if len(kernelRoutes) != 0 || len(manager.ownedRoutes) != 0 {
            t.Fatalf("replacement routes escaped disable cleanup: kernel=%#v owned=%#v", kernelRoutes, manager.ownedRoutes)
        }
    }

    func TestMissingDarwinInterfaceIsTransient(t *testing.T) {
        manager := newSystemRouteManager("sing-box-route-test-interface-does-not-exist", 1280, t.TempDir())
        _, err := manager.Update(true, netip.MustParseAddr("100.71.1.1"), netip.Addr{})
        if err == nil {
            t.Fatal("missing interface unexpectedly succeeded")
        }
        if !isTransientSystemRouteError(err) {
            t.Fatalf("missing interface error was classified as permanent: %v", err)
        }
    }
''')
darwin_tests.write_text(darwin_test_text)
