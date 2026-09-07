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

#### auto_config_kernel_parameter

Allow the provider to lease and restore the forwarding and per-interface sysctls required by the selected topology.

#### require_process_metadata

Fail startup if the WAN cgroup hooks needed by `process_name`, `process_path`, and `user_id` rules cannot be attached. When disabled, capture can start without those facts and matching degrades safely.

#### bpf_conn_state_map_size

Maximum eBPF connection-state entries. The default is `262144` and the minimum is `1024`.

### UDP NAT fields

See [UDP NAT fields](/configuration/shared/udp-nat/).

### Lifecycle and reload

The provider owns one listener set and sing-box owns one set of accept loops. Replacing an inbound with the same tag and identical capture settings switches the active sing-box handler without cloning sockets or starting a second eBPF dataplane. A second tag is rejected. Changing interfaces, port, mark, kernel configuration, metadata requirements, or map size requires a process restart.

If sing-box terminates without closing the provider, the next start refuses to delete ambiguous host state. After confirming no old sing-box process is active, recover with:

```bash
sudo sing-box tools dae cleanup-stale
```

Cleanup checks the provider ownership journal, process/boot identity, namespace identity, link tokens, TC slots, and BPF program IDs before removing anything.

### Build

```bash
go build -tags "with_dae,$(cat release/DEFAULT_BUILD_TAGS)" \
  -ldflags "$(cat release/LDFLAGS)" ./cmd/sing-box
```

Until the standalone provider is merged or tagged upstream, this fork pins the canonical provider module through a `replace` directive to `wignerStan/dae`.
