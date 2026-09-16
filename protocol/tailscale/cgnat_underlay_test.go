//go:build with_gvisor

package tailscale

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/tailscale/net/netmon"
)

func TestSystemInterfaceLeaseOwnsNetmonIdentity(t *testing.T) {
	first, err := acquireProcessHookLease(&Endpoint{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Release)
	if err := first.setSystemInterface("custom-tap", 42); err != nil {
		t.Fatal(err)
	}
	if name, err := netmon.TailscaleInterfaceName(); err != nil || name != "custom-tap" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	first.Release()
	if _, err := netmon.TailscaleInterfaceName(); err == nil {
		t.Fatal("closed endpoint left its interface registered")
	}
	if _, err := netmon.TailscaleInterfaceIndex(); err == nil {
		t.Fatal("closed endpoint left its interface index registered")
	}
	second, err := acquireProcessHookLease(&Endpoint{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Release)
	if err := second.setSystemInterface("new-tap", 43); err != nil {
		t.Fatal(err)
	}
	if err := first.setSystemInterface("stale-tap", 42); err == nil {
		t.Fatal("stale lease replaced current interface")
	}
	first.Release()
	if name, err := netmon.TailscaleInterfaceName(); err != nil || name != "new-tap" {
		t.Fatalf("stale release changed current identity: %q %v", name, err)
	}
	if err := second.setSystemInterface("", 0); err == nil {
		t.Fatal("accepted invalid identity")
	}
}

// Exercise the actual pinned dependency through its public API. Do not merely
// duplicate its policy in a sing-box helper or inspect source text.
func TestCGNATPhysicalCandidatesThroughPinnedDependency(t *testing.T) {
	lease, err := acquireProcessHookLease(&Endpoint{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Release)
	if err := lease.setSystemInterface("custom-tap", 42); err != nil {
		t.Fatal(err)
	}
	iface := func(name string, flags net.Flags, addr string) netmon.Interface {
		p := netip.MustParsePrefix(addr)
		return netmon.Interface{Interface: &net.Interface{Name: name, Flags: flags}, AltAddrs: []net.Addr{&net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}}}
	}
	physical := "100.65.10.7/16"
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) {
		return []netmon.Interface{
			iface("en0", net.FlagUp|net.FlagBroadcast, physical),
			iface("custom-tap", net.FlagUp|net.FlagBroadcast, "100.100.10.1/32"),
			iface("utun101", net.FlagUp|net.FlagPointToPoint, "100.100.10.2/32"),
			iface("tailscale0", net.FlagUp|net.FlagBroadcast, "100.100.10.3/32"),
		}, nil
	})
	for _, next := range []string{"100.65.10.7/16", "100.64.11.8/24"} {
		physical = next
		regular, _, err := netmon.LocalAddresses()
		want := netip.MustParsePrefix(physical).Addr()
		if err != nil || len(regular) != 1 || regular[0] != want {
			t.Fatalf("physical %s: candidates=%v err=%v", physical, regular, err)
		}
	}
}
