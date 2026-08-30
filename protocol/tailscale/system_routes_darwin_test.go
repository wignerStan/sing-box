//go:build with_gvisor && darwin

package tailscale

import (
	"net/netip"
	"syscall"
	"testing"

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
