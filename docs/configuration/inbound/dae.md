!!! quote "Custom Linux build"

    Build with `with_dae`. The inbound embeds the standalone dae capture provider in the sing-box process; it does not start the dae daemon or use IPC.

# dae eBPF

The `dae` inbound replaces the TUN/redirect capture layer while keeping sing-box as the only DNS, FakeIP, sniffing, routing, rule-set, and outbound authority.

```text
Linux TC/cgroup eBPF -> transparent TCP/UDP listeners -> sing-box router -> sing-box outbound
```

### Structure

```json
{
  "type": "dae",
  "tag": "dae-in",
  "lan_interface": ["eth0"],
  "wan_interface": ["auto"],
  "tproxy_port": 12345,
  "output_mark": "0x100",
  "auto_config_kernel_parameter": true,
  "require_process_metadata": true,
  "bpf_conn_state_map_size": 262144,

  "udp_timeout": "5m",
  "udp_mapping": "endpoint_independent",
  "udp_filtering": "endpoint_independent",
  "udp_nat_max": 16384
}
```

At least one LAN or WAN interface is required. The process must run as root and the kernel must support cgroup v2 and the required TC/eBPF features.

### Capture fields

#### lan_interface

Interfaces carrying forwarded client traffic. Use this on a router or exit-node LAN side.

#### wan_interface

Interfaces carrying locally generated and WAN-side traffic. The special value `auto` is resolved when the capture runtime starts. Restart sing-box after the default interface changes so the provider can attach to the new interface.

#### tproxy_port

Private transparent listener port. The default is `12345`.

#### output_mark

Mark applied to sing-box DNS, outbound, and transparent UDP reply sockets so their traffic is not captured again. The default is `0x100`. A `dae` inbound cannot coexist with another automatic capture owner, such as a TUN inbound with `auto_redirect`.

Do not set `route.default_mark` or `routing_mark` on DNS servers or outbounds when a `dae` inbound is configured. DAE applies `output_mark` automatically when its runtime starts, including to dialers created earlier. Configuration checks reject explicit marks before capture is attached.

#### bypass_mark and bypass_mark_mask

Optional kernel capture exemption for an existing network owner. With a nonzero
mask, packets for which `(packet_mark & bypass_mark_mask) == bypass_mark` remain
on the kernel path with their original mark. Both fields default to zero, which
disables this exemption. The mark must be nonzero and contain only masked bits.

For standalone Tailscale transport, use `"bypass_mark": "0x80000"` and
`"bypass_mark_mask": "0xff0000"`. This preserves Tailscale's socket identity and
policy routing. A userspace `direct` outbound does not provide that behavior.
Changing either field requires restarting sing-box.

#### auto_config_kernel_parameter

Allow the provider to lease and restore the forwarding and per-interface sysctls required by the selected topology.

#### require_process_metadata

Fail startup if the WAN cgroup hooks needed by `process_name`, `process_path`, and `user_id` rules cannot be attached. When disabled, capture can start without those facts and matching degrades safely.

#### bpf_conn_state_map_size

Maximum eBPF connection-state entries. The default is `262144` and the minimum is `1024`.

### UDP NAT fields

See [UDP NAT fields](/configuration/shared/udp-nat/).

### Lifecycle and reload

The provider owns one listener set and sing-box owns one set of accept loops. Replacing an inbound with the same tag and identical capture settings switches the active sing-box handler without cloning sockets or starting a second eBPF dataplane. A second tag is rejected. Changing interfaces, port, output or bypass marks, kernel configuration, metadata requirements, or map size requires a process restart.

If sing-box terminates without closing the provider, the next start refuses to delete ambiguous host state. After confirming no old sing-box process is active, recover with:

```bash
sudo sing-box tools dae cleanup-stale
```

Cleanup checks the provider ownership journal, process/boot identity, namespace identity, link tokens, TC slots, and BPF program IDs before removing anything.

If kernel capture teardown returns an error, sing-box deliberately retains the output-mark lease so residual hooks cannot recapture its own traffic. Clean the recorded stale state and restart the process instead of continuing with an ambiguous capture owner.

### Build

```bash
CGO_ENABLED=0 go build -tags "with_dae,$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" \
  -ldflags "$(cat release/LDFLAGS)" ./cmd/sing-box
```

The Naive outbound in `DEFAULT_BUILD_TAGS` requires the Chromium toolchain prepared by sing-box's release workflow; add `with_dae` to that workflow's tags when building the Naive variant.

The provider is generated from the pristine `third_party/dae` pin plus the ordered parent-owned `patches/dae` series. Build from the verified Go vendor projection; see [Vendor authority](/VENDOR_AUTHORITY/).
