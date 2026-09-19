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

`deps/source-relationships`, the ordered patch inventories, and the generated
vendor lock define the dependency identities. The verifier now checks the
relationship declarations against the lock, series order, projection paths,
and `.gitmodules` remotes, including in an offline source archive.

Reproduce the source projection with `python3 tools/vendor/materialize.py` and
validate it with `python3 tools/vendor/verify.py --require-source`. Build only
from the resulting standard Go vendor projection. The private logical workspace
outside the product checkout records original/rebased commits, tool versions,
commands, test results, and artifact digests; it is not a public dependency.
