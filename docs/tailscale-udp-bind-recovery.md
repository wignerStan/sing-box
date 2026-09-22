# Native UDP bind recovery

The physical-interface socket binder and Tailscale's network monitor can observe
the same network transition in different orders. If a UDP bind fails while the
physical default interface is unavailable, a later unchanged/minor notification
only runs ReSTUN. Previously that probed through a placeholder connection whose
writes reported success but transmitted nothing, potentially leaving the node
on DERP indefinitely.

Patch `patches/tailscale/0003-udp-bind-recovery.patch` makes a failed bind explicit
in each rebinding socket and returns the real bind error from placeholder writes.
Before endpoint discovery, the existing ReSTUN lifecycle retries only failed
sockets through the original physical-interface listener. Retries back off from
one to thirty seconds. No extra daemon, polling goroutine, or fallback unbound
socket is introduced. Healthy-family sockets and working relay connections are
not closed by this recovery path. Successful recovery refreshes port mapping,
PMTUD, peer path selection, and endpoint advertisement through existing paths.

The retry eligibility check and socket replacement share the rebinding socket
lock. Explicit socket closure clears retry state, and connection shutdown blocks
new binds. Intentionally disabled UDP is distinct from failed binding and is not
re-enabled by recovery.

Regression coverage lives in the canonical patch, not hand-edited vendor output:

```sh
python3 tools/vendor/materialize.py --keep-work
go test -mod=mod -race github.com/sagernet/tailscale/wgengine/magicsock \
  -run '^TestBindRecovery' -count=10
python3 tools/vendor/verify.py --require-source
```

The unchanged-network regression fails against the unmodified published base
`9a624c577bf79c14265cf2dbd5a85ab45feefd02`. Coverage includes startup bind failure,
late IPv4/IPv6 availability without disturbing the healthy family, bounded retry
frequency, network-down suppression, explicitly closed and disabled sockets,
and concurrent discovery/shutdown. All packet tests are loopback-only and do not
change production interfaces or routing.

This fixes socket recovery, not campus neighbor discovery. A working underlay is
still required; local CGNAT endpoint discovery is a separate existing patch.
