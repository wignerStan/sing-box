#!/usr/bin/env python3
"""One-shot source publisher, not a deployment or runtime helper."""
from pathlib import Path
import sys
root = Path(sys.argv[1])
def replace(path, old, new):
    file = root / path
    text = file.read_text()
    assert text.count(old) == 1, (path, text.count(old))
    file.write_text(text.replace(old, new))
replace('protocol/tailscale/process_hooks.go', '\treleased bool\n', '\treleased bool\n\tinterfaceProps bool\n')
replace('protocol/tailscale/process_hooks.go', 'func (l *processHookLease) Release() {', '''// setSystemInterface associates the real OS TUN with the same exclusive lease
// as the socket hooks. A stale lease cannot replace a newer endpoint's identity.
func (l *processHookLease) setSystemInterface(name string, index int) error {
\ttailscaleProcessHookRegistry.Lock()
\tdefer tailscaleProcessHookRegistry.Unlock()
\tif l == nil || l.released || tailscaleProcessHookRegistry.lease != l {
\t\treturn E.New("inactive Tailscale process-hook lease")
\t}
\tif name == "" || index <= 0 {
\t\treturn E.New("invalid Tailscale system-interface identity")
\t}
\tnetmon.SetTailscaleInterfaceProps(name, index)
\tl.interfaceProps = true
\treturn nil
}

func (l *processHookLease) Release() {''')
replace('protocol/tailscale/process_hooks.go', '\tnetmon.RegisterInterfaceGetter(nil)\n', '''\tif l.interfaceProps {
\t\tnetmon.SetTailscaleInterfaceProps("", 0)
\t}
\tnetmon.RegisterInterfaceGetter(nil)
''')
replace('protocol/tailscale/endpoint.go', '\t\tsystemDialer, err := dialer.NewDefault(t.ctx, option.DialerOptions{', '''\t\t// Use the actual allocated interface, not merely the requested name.
\t\t// Register it before tsnet enumerates physical endpoint candidates.
\t\ttunName, err = wgTunDevice.Name()
\t\tif err != nil {
\t\t\t_ = systemTun.Close()
\t\t\treturn E.Cause(err, "read Tailscale system-interface name")
\t\t}
\t\tsystemInterface, err := net.InterfaceByName(tunName)
\t\tif err != nil {
\t\t\t_ = systemTun.Close()
\t\t\treturn E.Cause(err, "resolve Tailscale system-interface identity")
\t\t}
\t\tif err = t.processHooks.setSystemInterface(tunName, systemInterface.Index); err != nil {
\t\t\t_ = systemTun.Close()
\t\t\treturn err
\t\t}
\t\tsystemDialer, err := dialer.NewDefault(t.ctx, option.DialerOptions{''')
(root/'protocol/tailscale/cgnat_underlay_test.go').write_text(r'''//go:build with_gvisor

package tailscale

import (
 "net"
 "net/netip"
 "testing"

 "github.com/sagernet/tailscale/net/netmon"
)

func TestSystemInterfaceLeaseOwnsNetmonIdentity(t *testing.T) {
 first, err := acquireProcessHookLease(&Endpoint{})
 if err != nil { t.Fatal(err) }
 t.Cleanup(first.Release)
 if err := first.setSystemInterface("custom-tap", 42); err != nil { t.Fatal(err) }
 if name, err := netmon.TailscaleInterfaceName(); err != nil || name != "custom-tap" { t.Fatalf("name=%q err=%v",name,err) }
 first.Release()
 if _, err := netmon.TailscaleInterfaceName(); err == nil { t.Fatal("closed endpoint left its interface registered") }
 if _, err := netmon.TailscaleInterfaceIndex(); err == nil { t.Fatal("closed endpoint left its interface index registered") }
 second, err := acquireProcessHookLease(&Endpoint{})
 if err != nil { t.Fatal(err) }
 t.Cleanup(second.Release)
 if err := second.setSystemInterface("new-tap",43); err != nil { t.Fatal(err) }
 if err := first.setSystemInterface("stale-tap",42); err == nil { t.Fatal("stale lease replaced current interface") }
 first.Release()
 if name, err := netmon.TailscaleInterfaceName(); err != nil || name != "new-tap" { t.Fatalf("stale release changed current identity: %q %v",name,err) }
 if err := second.setSystemInterface("",0); err == nil { t.Fatal("accepted invalid identity") }
}

// Exercise the actual pinned dependency through its public API. Do not merely
// duplicate its policy in a sing-box helper or inspect source text.
func TestCGNATPhysicalCandidatesThroughPinnedDependency(t *testing.T) {
 lease,err:=acquireProcessHookLease(&Endpoint{})
 if err!=nil { t.Fatal(err) }
 t.Cleanup(lease.Release)
 if err:=lease.setSystemInterface("custom-tap",42); err!=nil { t.Fatal(err) }
 iface:=func(name string,flags net.Flags,addr string) netmon.Interface {
  p:=netip.MustParsePrefix(addr)
  return netmon.Interface{Interface:&net.Interface{Name:name,Flags:flags},AltAddrs:[]net.Addr{&net.IPNet{IP:p.Addr().AsSlice(),Mask:net.CIDRMask(p.Bits(),p.Addr().BitLen())}}}
 }
 physical:="100.65.10.7/16"
 netmon.RegisterInterfaceGetter(func()([]netmon.Interface,error){
  return []netmon.Interface{
   iface("en0",net.FlagUp|net.FlagBroadcast,physical),
   iface("custom-tap",net.FlagUp|net.FlagBroadcast,"100.100.10.1/32"),
   iface("utun101",net.FlagUp|net.FlagPointToPoint,"100.100.10.2/32"),
   iface("tailscale0",net.FlagUp|net.FlagBroadcast,"100.100.10.3/32"),
  },nil
 })
 for _, next:=range []string{"100.65.10.7/16","100.64.11.8/24"} {
  physical=next
  regular,_,err:=netmon.LocalAddresses()
  want:=netip.MustParsePrefix(physical).Addr()
  if err!=nil || len(regular)!=1 || regular[0]!=want { t.Fatalf("physical %s: candidates=%v err=%v",physical,regular,err) }
 }
}
''')
(root/'docs/CGNAT_DIRECT_UDP.md').write_text('''# Native Tailscale direct IPv4 UDP on overlapping campus networks

## One runtime and one owner

The Mac runs the system-interface Tailscale endpoint inside sing-box. Do not
start standalone tailscaled, add a route supervisor, install a compatibility
socket, or create a second authenticated Tailscale state directory. The endpoint
registers its actual OS TUN name/index under the existing process-hook lease;
shutdown releases that registration without allowing a stale lease to clear a
newer endpoint. The scoped exit-route owner is unchanged. macOS still owns the
physical uplink's router-advertisement-derived IPv6 route.

## Configuration

Merge these fields into the existing authenticated Tailscale endpoint, retaining
its tag, state_directory, hostname, exit node, and other existing preferences:

```json
{
  "system_interface": true,
  "system_interface_name": "utun101",
  "listen_port": 41641
}
```

Use the existing route.auto_detect_interface setting for physical egress. Do not
bind the endpoint's transport dialer to utun101: that is the payload interface,
not the physical path to peers/control. Do not hard-code a campus DHCP address.
The port is configurable; choose a free port and allow that exact inbound UDP
port in the host firewall on both peers. A fixed port only makes firewall policy
predictable; it cannot bypass AP isolation or campus filtering.

The pinned Tailscale dependency now permits physical RFC 6598 candidates from
up, broadcast-capable Ethernet-like interfaces while excluding known Tailscale
interfaces, point-to-point/non-broadcast CGNAT tunnels, and Tailscale IPv6 ULA.
Enumeration remains dynamic across DHCP changes. Both Linux firewall backends
place the transport UDP exception before their CGNAT spoofing rules, without
removing the protections for other ports/protocols or forwarded traffic.

The Linux Incus peer also needs the matching Tailscale discovery/firewall change.
The fork provides a separate 1.94.2 backport so this does not require upgrading
that peer or adding a second daemon to the Mac. Keep the existing Linux state
and systemd service; the service must run the rebuilt backport binary. A package
update can replace a locally installed binary, so pin/manage it explicitly.
Do not use netfilter-mode=off or a blanket 100.64.0.0/10 ACCEPT rule.

## Native verification

Use the matching fork binary, with BOX_API_URL and BOX_API_SECRET set to the
existing authenticated sing-box management API (or the equivalent CLI flags):

```sh
sing-box api tailscale peer show incus
sing-box api tailscale ping incus
```

The current ping command may return success after relay replies, so inspect its
output: acceptance requires a direct physical IPv4 address:port, not DERP or
"direct connection not established". The standalone CLI on the Linux peer can
check its own current endpoints with tailscale status --json and tailscale ping.
Do not point the Mac's standalone tailscale CLI at utun101; a TUN is not LocalAPI.

Confirm in order: both current physical addresses are advertised; the selected
UDP listener is reachable through host firewalls; packets arrive in captures on
both physical interfaces; authenticated Tailscale ping selects a direct path.
An explicitly scoped physical route lookup can distinguish an overlapping
underlay address from an overlay route; do not add permanent broad CGNAT routes.

If probes leave one host but do not appear on the peer's physical interface,
that is not solved by an endpoint-discovery or local INPUT-rule change. The
campus path/AP isolation still needs diagnosis. Successful CI kernel UDP tests
are not proof of direct reachability on the user's Wi-Fi network.

## Regression coverage

Tests cover native interface registration/release, stale-lease protection,
physical CGNAT discovery through the pinned dependency, and DHCP changes. The
Tailscale companion includes Linux iptables/nftables packet tests in disposable
network namespaces, checking permitted UDP, blocked other UDP/TCP, port changes,
and removal. No test changes the production route table or deployment settings.
''')
