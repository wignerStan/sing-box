# Native Tailscale direct IPv4 UDP on overlapping campus networks

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
