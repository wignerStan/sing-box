!!! quote "Custom build"

    Linux only. Build with `-tags with_dae`. This inbound embeds dae's eBPF capture runtime directly; it does not start a dae daemon or use IPC.

# dae eBPF

The `dae` inbound replaces the TUN/redirect capture layer while keeping sing-box as the only DNS, FakeIP, sniffing, routing, rule-set, and outbound authority.

```text
tc/cgroup eBPF -> transparent TCP/UDP generation -> sing-box router -> sing-box outbound
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
  "bpf_conn_state_map_size": 262144,

  "udp_timeout": "5m",
  "udp_mapping": "endpoint_independent",
  "udp_filtering": "endpoint_independent",
  "udp_nat_max": 16384
}
```

At least one LAN or WAN interface is required. Interface values use dae's existing interface matcher syntax.

### Fields

#### lan_interface

Interfaces whose ingress traffic is captured. Use this for router/LAN traffic.

#### wan_interface

Interfaces whose locally generated egress traffic is captured. Process metadata is available when the required cgroup hooks can be attached.

#### tproxy_port

Internal transparent listener port. Default: `12345`.

#### output_mark

Socket mark applied to sing-box DNS and outbound sockets so dae does not capture them again. Default: `0x100`.

Only one auto-redirect output mark may be active in a sing-box process. Multiple `dae` generations may reuse the same mark during reload.

#### auto_config_kernel_parameter

Allow dae to configure required forwarding and interface sysctls.

#### bpf_conn_state_map_size

Maximum eBPF connection-state entries. Default: `262144`; minimum: `1024`.

### UDP NAT Fields

See [UDP NAT Fields](/configuration/shared/udp-nat/).

### Reload behavior

A same-configuration reload clones and atomically republishes the existing transparent listener generation. Changing capture interfaces, port, output mark, kernel-configuration mode, or map size currently requires a process restart.

### Build

```bash
go build -tags "with_dae,$(cat release/DEFAULT_BUILD_TAGS)" \
  -ldflags "$(cat release/LDFLAGS)" ./cmd/sing-box
```

The current provider is imported from the pinned dae fork revision in `go.mod`. The public `ebpfinbound` contract is policy-neutral; the provider implementation is still backed by dae's compatibility control plane and will be physically reduced in a later extraction.
