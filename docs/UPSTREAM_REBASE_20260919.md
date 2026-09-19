# Upstream integration provenance, 2026-09-19

The private integration starts from Wigner testing commit
`9a624c577bf79c14265cf2dbd5a85ab45feefd02` and rebases its downstream history onto
SagerNet testing commit `8330820fa62505f9574e4c35cd969d9af6eb7769`.

The downstream boundary is the original upstream snapshot
`60b504a1c74a33fe24872c8144c8f0b7d3d61b2a`. Upstream rewrote the intervening
upstream commits, so replaying from the graph merge base would incorrectly
reapply obsolete upstream implementations. Only the downstream range is
replayed, using `git rebase --rebase-merges`; published refs remain unchanged.

The native system dataplane fix `f4b650b23ceb69d565ed54562e198dc31e86fdf7`, Darwin
forwarder fix, interface identity ownership, CGNAT discovery, and DAE integration
were already present in the Wigner testing source. Their ownership and lifecycle
behavior are retained, with these explicit compatibility changes:

- Tailscale's embedded userspace stack now uses sing-tun Go rather than gVisor.
  Only the userspace wrapper receives `NetstackHandler` and implements `tun.Port`.
  A system-interface endpoint retains the real OS TUN as its sole payload path.
- Socket binding now uses upstream's per-server `ControlFunc` and
  `ListenPacketFunc`. The exclusive process lease remains for the global netmon
  interface getter and actual allocated system-interface identity.
- DAE output-mark leasing remains atomic while preserving upstream's new network
  monitor and reset lifecycle fields.

The embedded Tailscale pristine pin advances from
`c8e28eeffe16a390ae8e320500175de6207f521f` to
`a8fbeb4b0838c69e383e52b08228366f855d2261`, matching upstream's module version.
`patches/tailscale/0001-pure-system-dataplane.patch` is adapted to that API;
`0002-cgnat-direct-udp.patch` applies unchanged. The standalone Tailscale 1.94.2
backport pin and patch remain unchanged.

The DAE upstream pin remains `5db27a0028d36e7847bd3796497df952337a20e2`.
`patches/dae/0003-kernel-mark-bypass.patch` adds an opt-in mark/mask exemption
before capture, preserving the original kernel packet and mark. This is needed
for a standalone Tailscale daemon: a userspace direct outbound cannot preserve
its original socket identity. Both-zero defaults preserve existing behavior;
changing the exemption requires a process restart. The patch carries generated
BPF bytes and tests for both marked bypass and unmarked capture.

`0004-authoritative-output-mark.patch` fixes a separate existing feedback-loop
bug: a known socket-cookie PID could reject a packet before the provider's own
output-mark exemption ran. Cookie PIDs belong to the initial PID namespace, and
marked sockets can also belong to a different process. The capture-only early
check now treats the configured nonzero output mark as authoritative. A
controlled different-process `SO_MARK=0x1ee0` echo, with no userspace capture
reader, failed before the fix and passes afterward for TCP/UDP over IPv4/IPv6.
The privileged checks also verify that marks are unchanged in all eight TC
hooks, while unmarked traffic is still captured. The original standalone DAE
compilation path is unchanged. Product integration diagnostics now include the
child logs even when it has already exited before a shutdown signal.

`deps/source-relationships`, the ordered patch inventories, and the generated
vendor lock define the dependency identities. The verifier now checks the
relationship declarations against the lock, series order, projection paths,
and `.gitmodules` remotes, including in an offline source archive.

Reproduce the source projection with `python3 tools/vendor/materialize.py` and
validate it with `python3 tools/vendor/verify.py --require-source`. Build only
from the resulting standard Go vendor projection. The private logical workspace
outside the product checkout records original/rebased commits, tool versions,
commands, test results, and artifact digests; it is not a public dependency.

The first guarded real-host cutover exposed a configuration error that the
isolated datapath config did not contain: explicit per-DNS/per-outbound marks
and `route.default_mark` conflicted with DAE's automatic socket-mark lease.
The no-capture canary accepted those marks because it had no active lease.
The host was rolled back. Box construction now declares DAE mark ownership so
all default dialers reject explicit marks before startup, and `check` rejects
the route default immediately. Runtime conflict semantics remain unchanged.
Regression coverage includes DNS/outbound/default-mark check failures before
attachment and real TCP/UDP/packet sockets receiving the dynamically activated
lease mark without explicit marks. Canary bypass marks belong only to the
separate no-DAE configuration.

The second guarded cutover preserved SSH, exit traffic, public DNS and proxy
services, but exposed LAN-side UDP reply recapture for the host MagicDNS
resolver. Marked queries had bypassed capture; unmarked replies were looked up
in the provider namespace instead of the host socket namespace. Patch0005
checks current-namespace connected UDP socket ownership before conntrack and preserves
only replies to sockets carrying the configured own/bypass mark, without any
DNS-specific address or port exemption. The isolated before test failed all
six marked LAN UDP4/6 returns while TCP4/6 passed; after generation all twelve
LAN returns passed alongside the existing lifecycle/capture tests. The full
product fixture also exercises real LAN-side DNS replies through TCP and UDP
DNS client requests.

The exemption is deliberately limited to connected UDP sockets, whose complete
local/remote tuple proves ownership. Marked unconnected transparent reply-only
bindings and wildcard listeners can also match transit packets; they retain
existing capture behavior and have explicit negative regressions. Broader
unconnected LAN upstream handling requires separate destination-local proof.
A bounded raw L3 test-run experiment could not supply required protocol
metadata on this kernel; it is retained as a limitation rather than a passing
test. L2/L3 share the reviewed parser and classifier, and the guarded real
Tailscale interface probe remains required for final operational acceptance.
