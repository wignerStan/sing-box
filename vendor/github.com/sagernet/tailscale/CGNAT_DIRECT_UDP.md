# Direct UDP over an overlapping RFC 6598 underlay

This fork advertises CGNAT IPv4 addresses from up, broadcast-capable Ethernet-like
interfaces (Wi-Fi, Ethernet, bridges and veths). It excludes registered/conventional
Tailscale interfaces, loopback, point-to-point and unclassified non-broadcast
CGNAT interfaces, and the Tailscale IPv6 ULA. Addresses are re-enumerated rather
than cached, so DHCP changes do not require hard-coded endpoint addresses.

Both Linux firewall implementations put the existing magicsock UDP destination
port exception before CGNAT drop/return rules. Other UDP ports, TCP and forwarded
traffic retain their existing protections. This does not disable netfilter or
add a blanket CGNAT allow. The UDP listener still authenticates transport packets.

For a sing-box system endpoint, use the matching sing-box integration and a fixed
`listen_port` when a host firewall needs a stable destination port. The Linux
standalone peer needs this discovery/firewall fix too. Updating only the Mac
cannot make an unadvertised/filtered peer reachable.

A campus AP/controller can still block station-to-station UDP. Passing these
regression tests is not proof of reachability on that physical network. Confirm
both peers advertise their current underlay addresses and that native Tailscale
ping reports a direct physical address:port rather than DERP. Packet captures
must distinguish no packet reaching an interface from a local firewall drop.

The kernel test is deliberately opt-in (`cgnat_integration` build tag), requires
root and a fixture interface, and is run only in disposable network namespaces.
It verifies UDP round trips, rejects a different UDP port and TCP on the same
port, then verifies port replacement and cleanup with iptables and nftables.
