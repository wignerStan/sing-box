//go:build with_gvisor && darwin

package tailscale

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestScopedRouteMessageUsesInterfaceGateway(t *testing.T) {
	tests := []struct {
		name   string
		family systemRouteFamily
		addr   netip.Addr
		want   route.Addr
	}{
		{name: "ipv4", family: systemRouteIPv4, addr: netip.MustParseAddr("100.71.1.1"), want: &route.Inet4Addr{}},
		{name: "ipv6", family: systemRouteIPv6, addr: netip.MustParseAddr("fd7a:115c:a1e0::1"), want: &route.Inet6Addr{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := scopedRouteMessage(unix.RTM_ADD, systemRoute{family: tt.family, gateway: tt.addr, index: 17}, 23, 29)
			if err != nil {
				t.Fatal(err)
			}
			if msg.Flags&unix.RTF_IFSCOPE == 0 {
				t.Fatalf("flags %#x do not include RTF_IFSCOPE", msg.Flags)
			}
			if msg.Flags&unix.RTF_GATEWAY != 0 {
				t.Fatalf("flags %#x unexpectedly include RTF_GATEWAY", msg.Flags)
			}
			if msg.Index != 17 {
				t.Fatalf("route index = %d, want 17", msg.Index)
			}
			link, ok := msg.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
			if !ok || link.Index != 17 {
				t.Fatalf("gateway = %#v, want LinkAddr index 17", msg.Addrs[syscall.RTAX_GATEWAY])
			}
			if got := msg.Addrs[syscall.RTAX_IFA]; got == nil || got.Family() != tt.want.Family() {
				t.Fatalf("interface address = %#v, want family %d", got, tt.want.Family())
			}
		})
	}
}

type fakeSystemRouteCall struct {
	typ   int
	route systemRoute
}

func newFakeSystemRouteManager(indexes func() (int, int, error), op func(int, systemRoute) error) *darwinSystemRouteManager {
	manager := &darwinSystemRouteManager{
		name:         "utun-test",
		mtu:          1280,
		routes:       make(map[systemRouteFamily]systemRoute),
		missingSince: make(map[systemRouteFamily]time.Time),
		indexes:      indexes,
		routeOp:      op,
		now:          time.Now,
	}
	return manager
}

func TestNewSystemRouteManagerInitializesProductionDependencies(t *testing.T) {
	manager, ok := newSystemRouteManager("utun-test", 1280, t.TempDir()).(*darwinSystemRouteManager)
	if !ok {
		t.Fatalf("manager type = %T, want *darwinSystemRouteManager", manager)
	}
	if manager.name != "utun-test" || manager.mtu != 1280 {
		t.Fatalf("manager = {name:%q mtu:%d}, want {name:%q mtu:%d}", manager.name, manager.mtu, "utun-test", 1280)
	}
	if manager.routes == nil || manager.indexes == nil || manager.routeOp == nil {
		t.Fatalf("manager dependencies are incomplete: routes=%v indexes=%v routeOp=%v", manager.routes != nil, manager.indexes != nil, manager.routeOp != nil)
	}
}

func TestSystemRouteManagerReconcilesFamilies(t *testing.T) {
	ip4 := netip.MustParseAddr("100.71.1.1")
	ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	var calls []fakeSystemRouteCall
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, route systemRoute) error {
		calls = append(calls, fakeSystemRouteCall{typ: typ, route: route})
		return nil
	})

	if err := manager.Update(true, ip4, ip6); err != nil {
		t.Fatal(err)
	}
	wantRoutes := map[systemRouteFamily]systemRoute{
		systemRouteIPv4: {family: systemRouteIPv4, gateway: ip4, index: 17, mtu: 1280},
		systemRouteIPv6: {family: systemRouteIPv6, gateway: ip6, index: 17, mtu: 1280},
	}
	if !reflect.DeepEqual(manager.routes, wantRoutes) {
		t.Fatalf("routes after enable = %#v, want %#v", manager.routes, wantRoutes)
	}
	wantCalls := []fakeSystemRouteCall{
		{typ: unix.RTM_ADD, route: wantRoutes[systemRouteIPv4]},
		{typ: unix.RTM_ADD, route: wantRoutes[systemRouteIPv6]},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls after enable = %#v, want %#v", calls, wantCalls)
	}

	if err := manager.Update(true, ip4, ip6); err != nil {
		t.Fatal(err)
	}
	wantCalls = append(wantCalls,
		fakeSystemRouteCall{typ: unix.RTM_CHANGE, route: wantRoutes[systemRouteIPv4]},
		fakeSystemRouteCall{typ: unix.RTM_CHANGE, route: wantRoutes[systemRouteIPv6]},
	)
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("idempotent update calls = %#v, want %#v", calls, wantCalls)
	}

	if err := manager.Update(true, ip4, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	wantCalls = append(wantCalls,
		fakeSystemRouteCall{typ: unix.RTM_CHANGE, route: wantRoutes[systemRouteIPv4]},
	)
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls during IPv6 handover = %#v, want %#v", calls, wantCalls)
	}
	if !reflect.DeepEqual(manager.routes, wantRoutes) {
		t.Fatalf("routes during IPv6 handover = %#v, want %#v", manager.routes, wantRoutes)
	}

	if err := manager.Update(false, ip4, ip6); err != nil {
		t.Fatal(err)
	}
	wantCalls = append(wantCalls,
		fakeSystemRouteCall{typ: unix.RTM_DELETE, route: wantRoutes[systemRouteIPv4]},
		fakeSystemRouteCall{typ: unix.RTM_DELETE, route: wantRoutes[systemRouteIPv6]},
	)
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls after disable = %#v, want %#v", calls, wantCalls)
	}
	if len(manager.routes) != 0 {
		t.Fatalf("routes after disable = %#v, want empty", manager.routes)
	}
}

func TestSystemRouteManagerRotatesAddressInterfaceAndMTU(t *testing.T) {
	oldIP := netip.MustParseAddr("100.71.1.1")
	newIP := netip.MustParseAddr("100.72.2.2")
	index := 17
	var calls []fakeSystemRouteCall
	manager := newFakeSystemRouteManager(func() (int, int, error) { return index, index, nil }, func(typ int, route systemRoute) error {
		calls = append(calls, fakeSystemRouteCall{typ: typ, route: route})
		return nil
	})
	if err := manager.Update(true, oldIP, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	index = 19
	manager.mtu = 1360
	if err := manager.Update(true, newIP, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	want := []fakeSystemRouteCall{
		{typ: unix.RTM_ADD, route: systemRoute{family: systemRouteIPv4, gateway: oldIP, index: 17, mtu: 1280}},
		{typ: unix.RTM_ADD, route: systemRoute{family: systemRouteIPv4, gateway: newIP, index: 19, mtu: 1360}},
		{typ: unix.RTM_DELETE, route: systemRoute{family: systemRouteIPv4, gateway: oldIP, index: 17, mtu: 1280}},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
	if got := manager.routes[systemRouteIPv4]; got != want[1].route {
		t.Fatalf("current route = %#v, want %#v", got, want[1].route)
	}
}

func TestSystemRouteManagerChangesAddressAndMTUInPlace(t *testing.T) {
	oldIP := netip.MustParseAddr("100.71.1.1")
	newIP := netip.MustParseAddr("100.72.2.2")
	var calls []fakeSystemRouteCall
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, route systemRoute) error {
		calls = append(calls, fakeSystemRouteCall{typ: typ, route: route})
		return nil
	})
	if err := manager.Update(true, oldIP, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	manager.mtu = 1360
	if err := manager.Update(true, newIP, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	want := []fakeSystemRouteCall{
		{typ: unix.RTM_ADD, route: systemRoute{family: systemRouteIPv4, gateway: oldIP, index: 17, mtu: 1280}},
		{typ: unix.RTM_CHANGE, route: systemRoute{family: systemRouteIPv4, gateway: newIP, index: 17, mtu: 1360}},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
}

func TestSystemRouteManagerPreservesOldRouteWhenReplacementInstallFails(t *testing.T) {
	oldIP := netip.MustParseAddr("100.71.1.1")
	newIP := netip.MustParseAddr("100.72.2.2")
	index := 17
	sentinel := errors.New("install replacement failed")
	var calls []fakeSystemRouteCall
	manager := newFakeSystemRouteManager(func() (int, int, error) { return index, index, nil }, func(typ int, route systemRoute) error {
		calls = append(calls, fakeSystemRouteCall{typ: typ, route: route})
		if typ == unix.RTM_ADD && route.index == 19 {
			return sentinel
		}
		return nil
	})
	if err := manager.Update(true, oldIP, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	oldRoute := manager.routes[systemRouteIPv4]
	index = 19
	if err := manager.Update(true, newIP, netip.Addr{}); !errors.Is(err, sentinel) {
		t.Fatalf("replacement error = %v, want %v", err, sentinel)
	}
	if got := manager.routes[systemRouteIPv4]; got != oldRoute {
		t.Fatalf("working route changed after failed replacement: got %#v, want %#v", got, oldRoute)
	}
	for _, call := range calls[1:] {
		if call.typ == unix.RTM_DELETE && call.route == oldRoute {
			t.Fatal("old working route was deleted after replacement installation failed")
		}
	}
}

func TestSystemRouteManagerRollsBackReplacementWhenOldDeleteFails(t *testing.T) {
	oldIP := netip.MustParseAddr("100.71.1.1")
	newIP := netip.MustParseAddr("100.72.2.2")
	index := 17
	sentinel := errors.New("delete old failed")
	var oldRoute systemRoute
	var newRoute systemRoute
	var calls []fakeSystemRouteCall
	manager := newFakeSystemRouteManager(func() (int, int, error) { return index, index, nil }, func(typ int, route systemRoute) error {
		calls = append(calls, fakeSystemRouteCall{typ: typ, route: route})
		if typ == unix.RTM_DELETE && route == oldRoute && route.index == 17 {
			return sentinel
		}
		return nil
	})
	if err := manager.Update(true, oldIP, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	oldRoute = manager.routes[systemRouteIPv4]
	index = 19
	newRoute = systemRoute{family: systemRouteIPv4, gateway: newIP, index: 19, mtu: 1280}
	if err := manager.Update(true, newIP, netip.Addr{}); !errors.Is(err, sentinel) {
		t.Fatalf("replacement error = %v, want %v", err, sentinel)
	}
	if got := manager.routes[systemRouteIPv4]; got != oldRoute {
		t.Fatalf("bookkeeping after rollback = %#v, want old route %#v", got, oldRoute)
	}
	wantTail := []fakeSystemRouteCall{
		{typ: unix.RTM_ADD, route: newRoute},
		{typ: unix.RTM_DELETE, route: oldRoute},
		{typ: unix.RTM_DELETE, route: newRoute},
	}
	if len(calls) < len(wantTail) || !reflect.DeepEqual(calls[len(calls)-len(wantTail):], wantTail) {
		t.Fatalf("replacement tail = %#v, want %#v", calls, wantTail)
	}
}

func TestSystemRouteManagerExpiresMissingFamilyAfterGrace(t *testing.T) {
	ip4 := netip.MustParseAddr("100.71.1.1")
	ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	now := time.Unix(100, 0)
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(int, systemRoute) error { return nil })
	manager.now = func() time.Time { return now }
	if err := manager.Update(true, ip4, ip6); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(true, ip4, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if _, loaded := manager.routes[systemRouteIPv6]; !loaded {
		t.Fatal("IPv6 route was removed before the handover grace expired")
	}
	now = now.Add(systemRouteHandoverGrace + time.Millisecond)
	if err := manager.Update(true, ip4, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if _, loaded := manager.routes[systemRouteIPv6]; loaded {
		t.Fatal("stale IPv6 route survived past the handover grace")
	}
}

func TestSystemRouteManagerDropsMissingFamilyOnInterfaceReplacement(t *testing.T) {
	ip4 := netip.MustParseAddr("100.71.1.1")
	ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	index := 17
	manager := newFakeSystemRouteManager(func() (int, int, error) { return index, index, nil }, func(int, systemRoute) error { return nil })
	if err := manager.Update(true, ip4, ip6); err != nil {
		t.Fatal(err)
	}
	index = 19
	if err := manager.Update(true, ip4, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if _, loaded := manager.routes[systemRouteIPv6]; loaded {
		t.Fatal("IPv6 route retained the stale utun scope after interface replacement")
	}
}

func TestSystemRouteManagerRepairsExistingRoute(t *testing.T) {
	ip4 := netip.MustParseAddr("100.71.1.1")
	var calls []fakeSystemRouteCall
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, route systemRoute) error {
		calls = append(calls, fakeSystemRouteCall{typ: typ, route: route})
		if typ == unix.RTM_ADD {
			return unix.EEXIST
		}
		return nil
	})
	if err := manager.Update(true, ip4, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	wantRoute := systemRoute{family: systemRouteIPv4, gateway: ip4, index: 17, mtu: 1280}
	wantCalls := []fakeSystemRouteCall{{typ: unix.RTM_ADD, route: wantRoute}, {typ: unix.RTM_CHANGE, route: wantRoute}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	if got, ok := manager.routes[systemRouteIPv4]; !ok || got != wantRoute {
		t.Fatalf("adopted route = %#v, present=%v; want %#v", got, ok, wantRoute)
	}
}

func TestSystemRouteManagerDoesNotAdoptUnrepairableRoute(t *testing.T) {
	sentinel := errors.New("change failed")
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, _ systemRoute) error {
		if typ == unix.RTM_ADD {
			return unix.EEXIST
		}
		return sentinel
	})
	err := manager.Update(true, netip.MustParseAddr("100.71.1.1"), netip.Addr{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want %v", err, sentinel)
	}
	if len(manager.routes) != 0 {
		t.Fatalf("unrepairable route was recorded: %#v", manager.routes)
	}
}

func TestSystemRouteManagerPreservesSuccessfulFamily(t *testing.T) {
	ip4 := netip.MustParseAddr("100.71.1.1")
	ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	failIPv6 := true
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, route systemRoute) error {
		if failIPv6 && typ == unix.RTM_ADD && route.family == systemRouteIPv6 {
			return unix.ENXIO
		}
		return nil
	})
	if err := manager.Update(true, ip4, ip6); !errors.Is(err, unix.ENXIO) {
		t.Fatalf("first update error = %v, want ENXIO", err)
	}
	if _, ok := manager.routes[systemRouteIPv4]; !ok {
		t.Fatal("successful IPv4 route was discarded when IPv6 failed")
	}
	if _, ok := manager.routes[systemRouteIPv6]; ok {
		t.Fatal("failed IPv6 route was recorded")
	}
	failIPv6 = false
	if err := manager.Update(true, ip4, ip6); err != nil {
		t.Fatal(err)
	}
	if len(manager.routes) != 2 {
		t.Fatalf("routes after IPv6 retry = %#v, want both families", manager.routes)
	}
}

func TestSystemRouteManagerReportsBothFamilyErrors(t *testing.T) {
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, route systemRoute) error {
		if typ != unix.RTM_ADD {
			return nil
		}
		if route.family == systemRouteIPv4 {
			return unix.EPERM
		}
		return unix.ENETUNREACH
	})
	err := manager.Update(true, netip.MustParseAddr("100.71.1.1"), netip.MustParseAddr("fd7a:115c:a1e0::1"))
	if !errors.Is(err, unix.EPERM) || !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("error = %v, want both EPERM and ENETUNREACH", err)
	}
	if len(manager.routes) != 0 {
		t.Fatalf("routes after failed update = %#v, want empty", manager.routes)
	}
}

func TestSystemRouteManagerRejectsInvalidInterfaceIndex(t *testing.T) {
	for _, index := range []int{0, -1, 0x10000} {
		t.Run(fmt.Sprintf("index-%d", index), func(t *testing.T) {
			called := false
			manager := newFakeSystemRouteManager(func() (int, int, error) { return index, index, nil }, func(int, systemRoute) error {
				called = true
				return nil
			})
			err := manager.Update(true, netip.MustParseAddr("100.71.1.1"), netip.Addr{})
			if !errors.Is(err, unix.EINVAL) {
				t.Fatalf("error = %v, want EINVAL", err)
			}
			if called {
				t.Fatal("route operation ran with an invalid interface index")
			}
		})
	}
}

func TestSystemRouteManagerRetriesReplaceRace(t *testing.T) {
	var calls []int
	changeCount := 0
	addCount := 0
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, _ systemRoute) error {
		calls = append(calls, typ)
		switch typ {
		case unix.RTM_ADD:
			addCount++
			if addCount == 1 {
				return unix.EEXIST
			}
		case unix.RTM_CHANGE:
			changeCount++
			if changeCount == 1 {
				return unix.ESRCH
			}
		}
		return nil
	})
	if err := manager.Update(true, netip.MustParseAddr("100.71.1.1"), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if want := []int{unix.RTM_ADD, unix.RTM_CHANGE, unix.RTM_ADD}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
	if len(manager.routes) != 1 {
		t.Fatalf("routes = %#v, want one repaired route", manager.routes)
	}
}

func TestSystemRouteManagerRetriesReplaceRaceWithSecondConflict(t *testing.T) {
	var calls []int
	changeCount := 0
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, _ systemRoute) error {
		calls = append(calls, typ)
		switch typ {
		case unix.RTM_ADD:
			return unix.EEXIST
		case unix.RTM_CHANGE:
			changeCount++
			if changeCount == 1 {
				return unix.ESRCH
			}
		}
		return nil
	})
	if err := manager.Update(true, netip.MustParseAddr("100.71.1.1"), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	want := []int{unix.RTM_ADD, unix.RTM_CHANGE, unix.RTM_ADD, unix.RTM_CHANGE}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
	if len(manager.routes) != 1 {
		t.Fatalf("routes = %#v, want one repaired route", manager.routes)
	}
}

func TestSystemRouteManagerPreservesStateOnDeleteFailure(t *testing.T) {
	sentinel := errors.New("delete failed")
	failDelete := true
	var calls []fakeSystemRouteCall
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, route systemRoute) error {
		calls = append(calls, fakeSystemRouteCall{typ: typ, route: route})
		if typ == unix.RTM_DELETE && failDelete {
			return sentinel
		}
		return nil
	})
	ip4 := netip.MustParseAddr("100.71.1.1")
	if err := manager.Update(true, ip4, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(false, netip.Addr{}, netip.Addr{}); !errors.Is(err, sentinel) {
		t.Fatalf("disable error = %v, want %v", err, sentinel)
	}
	if len(manager.routes) != 1 {
		t.Fatalf("route bookkeeping lost after failed delete: %#v", manager.routes)
	}
	failDelete = false
	if err := manager.Update(false, netip.Addr{}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if len(manager.routes) != 0 {
		t.Fatalf("route bookkeeping after retry = %#v, want empty", manager.routes)
	}
	if len(calls) != 3 {
		t.Fatalf("calls = %#v, want add + failed delete + delete", calls)
	}
}

func TestSystemRouteManagerCloseRetriesFailedDelete(t *testing.T) {
	failIPv4Delete := true
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, route systemRoute) error {
		if typ == unix.RTM_DELETE && route.family == systemRouteIPv4 && failIPv4Delete {
			return unix.EPERM
		}
		return nil
	})
	if err := manager.Update(true, netip.MustParseAddr("100.71.1.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("first close error = %v, want EPERM", err)
	}
	if manager.closed || !manager.closing {
		t.Fatalf("state after failed close: closed=%v closing=%v", manager.closed, manager.closing)
	}
	if _, ok := manager.routes[systemRouteIPv4]; !ok {
		t.Fatal("failed IPv4 deletion was not retained for retry")
	}
	if _, ok := manager.routes[systemRouteIPv6]; ok {
		t.Fatal("successfully deleted IPv6 route was retained")
	}
	if err := manager.Update(true, netip.MustParseAddr("100.71.1.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("update during close = %v, want net.ErrClosed", err)
	}
	failIPv4Delete = false
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if !manager.closed || len(manager.routes) != 0 {
		t.Fatalf("state after close retry: closed=%v routes=%#v", manager.closed, manager.routes)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("idempotent close = %v", err)
	}
}

func TestSystemRouteManagerMissingInterface(t *testing.T) {
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 0, 0, unix.ENXIO }, func(int, systemRoute) error {
		return unix.ENXIO
	})
	if err := manager.Update(true, netip.MustParseAddr("100.71.1.1"), netip.Addr{}); !errors.Is(err, unix.ENXIO) {
		t.Fatalf("enabled update error = %v, want ENXIO", err)
	}
	manager.routes[systemRouteIPv4] = systemRoute{family: systemRouteIPv4, gateway: netip.MustParseAddr("100.71.1.1"), index: 17, mtu: 1280}
	if err := manager.Update(false, netip.Addr{}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if len(manager.routes) != 0 {
		t.Fatalf("routes after missing-interface disable = %#v, want empty", manager.routes)
	}
}

func TestSystemRouteManagerNoAddressesDoesNotNeedInterface(t *testing.T) {
	called := false
	manager := newFakeSystemRouteManager(func() (int, int, error) {
		called = true
		return 0, 0, unix.ENXIO
	}, func(int, systemRoute) error {
		return nil
	})
	if err := manager.Update(true, netip.Addr{}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("interface lookup was attempted without an address to install")
	}
	manager.routes[systemRouteIPv4] = systemRoute{
		family:  systemRouteIPv4,
		gateway: netip.MustParseAddr("100.71.1.1"),
		index:   17,
		mtu:     1280,
	}
	if err := manager.Update(true, netip.Addr{}, netip.Addr{}); !errors.Is(err, unix.ENXIO) {
		t.Fatalf("handover without a current interface error = %v, want ENXIO", err)
	}
	if _, ok := manager.routes[systemRouteIPv4]; !ok {
		t.Fatal("existing route bookkeeping was discarded after failed interface validation")
	}
}

func TestSystemRouteManagerRefreshesMissingRoute(t *testing.T) {
	missing := true
	var calls []int
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, _ systemRoute) error {
		calls = append(calls, typ)
		if typ == unix.RTM_CHANGE && missing {
			missing = false
			return unix.ESRCH
		}
		return nil
	})
	ip4 := netip.MustParseAddr("100.71.1.1")
	if err := manager.Update(true, ip4, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if want := []int{unix.RTM_ADD}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("initial calls = %#v, want %#v", calls, want)
	}
	if err := manager.Update(true, ip4, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if want := []int{unix.RTM_ADD, unix.RTM_CHANGE, unix.RTM_ADD}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("repair calls = %#v, want %#v", calls, want)
	}
}

func TestSystemRouteManagerRefreshErrorPreservesBookkeeping(t *testing.T) {
	sentinel := errors.New("refresh failed")
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(typ int, _ systemRoute) error {
		if typ == unix.RTM_CHANGE {
			return sentinel
		}
		return nil
	})
	ip4 := netip.MustParseAddr("100.71.1.1")
	if err := manager.Update(true, ip4, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(true, ip4, netip.Addr{}); !errors.Is(err, sentinel) {
		t.Fatalf("refresh error = %v, want %v", err, sentinel)
	}
	if _, ok := manager.routes[systemRouteIPv4]; !ok {
		t.Fatal("refresh failure unexpectedly discarded route bookkeeping")
	}
}

func TestSystemRouteManagerConcurrentLifecycle(t *testing.T) {
	var callsMu sync.Mutex
	var calls int
	manager := newFakeSystemRouteManager(func() (int, int, error) { return 17, 17, nil }, func(int, systemRoute) error {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		return nil
	})
	ip4 := netip.MustParseAddr("100.71.1.1")
	ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	if err := manager.Update(true, ip4, ip6); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				_ = manager.Update(j%2 == 0, ip4, ip6)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_ = manager.Close()
	}()
	close(start)
	wg.Wait()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	if calls == 0 {
		t.Fatal("concurrent lifecycle made no route operations")
	}
}

func TestScopedRouteMessageValidation(t *testing.T) {
	base := systemRoute{family: systemRouteIPv4, gateway: netip.MustParseAddr("100.71.1.1"), index: 17}
	tests := []struct {
		name  string
		route systemRoute
		typ   int
		want  error
	}{
		{name: "bad type", route: base, typ: unix.RTM_GET, want: unix.EINVAL},
		{name: "bad index", route: systemRoute{family: base.family, gateway: base.gateway}, typ: unix.RTM_ADD, want: unix.EINVAL},
		{name: "bad gateway", route: systemRoute{family: base.family, index: 17}, typ: unix.RTM_ADD, want: unix.EINVAL},
		{name: "unspecified ipv4", route: systemRoute{family: systemRouteIPv4, gateway: netip.IPv4Unspecified(), index: 17}, typ: unix.RTM_ADD, want: unix.EINVAL},
		{name: "unspecified ipv6", route: systemRoute{family: systemRouteIPv6, gateway: netip.IPv6Unspecified(), index: 17}, typ: unix.RTM_ADD, want: unix.EINVAL},
		{name: "zoned ipv6", route: systemRoute{family: systemRouteIPv6, gateway: netip.MustParseAddr("fd7a:115c:a1e0::1%utun-test"), index: 17}, typ: unix.RTM_ADD, want: unix.EINVAL},
		{name: "ipv4 with ipv6", route: systemRoute{family: systemRouteIPv4, gateway: netip.MustParseAddr("fd7a:115c:a1e0::1"), index: 17}, typ: unix.RTM_ADD, want: unix.EAFNOSUPPORT},
		{name: "ipv6 mapped ipv4", route: systemRoute{family: systemRouteIPv6, gateway: netip.MustParseAddr("::ffff:100.71.1.1"), index: 17}, typ: unix.RTM_ADD, want: unix.EAFNOSUPPORT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := scopedRouteMessage(tt.typ, tt.route, 23, 29)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestScopedRouteMessageOperationFlags(t *testing.T) {
	r := systemRoute{family: systemRouteIPv4, gateway: netip.MustParseAddr("100.71.1.1"), index: 17}
	for _, typ := range []int{unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE} {
		msg, err := scopedRouteMessage(typ, r, 23, 29)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Flags&(unix.RTF_STATIC|unix.RTF_IFSCOPE) != unix.RTF_STATIC|unix.RTF_IFSCOPE {
			t.Fatalf("type %d flags %#x missing static/ifscope", typ, msg.Flags)
		}
		if typ == unix.RTM_ADD && msg.Flags&unix.RTF_UP == 0 {
			t.Fatalf("add flags %#x missing RTF_UP", msg.Flags)
		}
		if typ == unix.RTM_DELETE && msg.Flags&unix.RTF_UP != 0 {
			t.Fatalf("type %d flags %#x unexpectedly include RTF_UP", typ, msg.Flags)
		}
		if typ == unix.RTM_CHANGE && msg.Flags&unix.RTF_UP == 0 {
			t.Fatalf("change flags %#x missing RTF_UP", msg.Flags)
		}
		if msg.Flags&unix.RTF_GATEWAY != 0 {
			t.Fatalf("type %d flags %#x unexpectedly include RTF_GATEWAY", typ, msg.Flags)
		}
	}
}

func TestMarshalScopedRouteMessageIncludesMTU(t *testing.T) {
	r := systemRoute{family: systemRouteIPv4, gateway: netip.MustParseAddr("100.71.1.1"), index: 17, mtu: 1280}
	request, err := marshalScopedRouteMessage(unix.RTM_ADD, r, 23, 29)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(request[darwinRouteInitsOffset : darwinRouteInitsOffset+4]); got != uint32(unix.RTV_MTU) {
		t.Fatalf("rtm_inits = %#x, want %#x", got, unix.RTV_MTU)
	}
	if got := binary.LittleEndian.Uint32(request[darwinRouteLocksOffset : darwinRouteLocksOffset+4]); got != uint32(unix.RTV_MTU) {
		t.Fatalf("rmx_locks = %#x, want %#x", got, unix.RTV_MTU)
	}
	if got := binary.LittleEndian.Uint32(request[darwinRouteMTUOffset : darwinRouteMTUOffset+4]); got != r.mtu {
		t.Fatalf("rmx_mtu = %d, want %d", got, r.mtu)
	}
	deleteRequest, err := marshalScopedRouteMessage(unix.RTM_DELETE, r, 23, 29)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(deleteRequest[darwinRouteInitsOffset : darwinRouteInitsOffset+4]); got != 0 {
		t.Fatalf("delete rtm_inits = %#x, want zero", got)
	}
	if got := binary.LittleEndian.Uint32(deleteRequest[darwinRouteLocksOffset : darwinRouteLocksOffset+4]); got != 0 {
		t.Fatalf("delete rmx_locks = %#x, want zero", got)
	}
	if got := binary.LittleEndian.Uint32(deleteRequest[darwinRouteMTUOffset : darwinRouteMTUOffset+4]); got != 0 {
		t.Fatalf("delete rmx_mtu = %d, want zero", got)
	}
}

func TestIsRouteGoneHandlesWrappedErrors(t *testing.T) {
	for _, err := range []error{unix.ESRCH, unix.ENOENT, unix.ENXIO} {
		if !isRouteGone(errors.Join(errors.New("context"), err)) {
			t.Fatalf("isRouteGone(%v) = false", err)
		}
	}
	if isRouteGone(unix.EPERM) {
		t.Fatal("EPERM was treated as a gone route")
	}
}

func FuzzScopedRouteMessageValidation(f *testing.F) {
	f.Add(uint8(4), []byte{100, 71, 1, 1}, 17, uint8(unix.RTM_ADD), uint32(1280))
	f.Add(uint8(6), []byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 17, uint8(unix.RTM_CHANGE), uint32(1280))
	f.Fuzz(func(t *testing.T, family uint8, raw []byte, index int, typ uint8, mtu uint32) {
		var addr netip.Addr
		switch systemRouteFamily(family) {
		case systemRouteIPv4:
			if len(raw) < net.IPv4len {
				return
			}
			var bytes [net.IPv4len]byte
			copy(bytes[:], raw)
			addr = netip.AddrFrom4(bytes)
		case systemRouteIPv6:
			if len(raw) < net.IPv6len {
				return
			}
			var bytes [net.IPv6len]byte
			copy(bytes[:], raw)
			addr = netip.AddrFrom16(bytes)
		default:
			addr = netip.Addr{}
		}
		route := systemRoute{family: systemRouteFamily(family), gateway: addr, index: index, mtu: mtu}
		_, _ = scopedRouteMessage(int(typ), route, 23, 29)
		_, _ = marshalScopedRouteMessage(int(typ), route, 23, 29)
	})
}
