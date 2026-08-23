# dae

Linux only. Android is not supported.

The `dae` inbound adopts the transparent TCP and UDP listeners created by
dae's TC/cgroup eBPF datapath. sing-box then handles the original sockets with
its normal sniffing, DNS, FakeIP, routing, and outbound pipeline.

```json
{
  "type": "dae",
  "tag": "dae-in",
  "socket_path": "/run/dae/sing-box.sock",
  "socket_mode": 384,
  "producer_uid": 0,
  "output_mark": "0x100",
  "metadata_timeout": "1s",
  "udp_timeout": "5m",
  "udp_mapping": "endpoint-independent",
  "udp_filtering": "endpoint-independent",
  "udp_nat_max": 0
}
```

## Fields

### socket_path

Required.

Absolute path of the Unix `SOCK_SEQPACKET` control socket created by
sing-box. Start this inbound before dae.

Set the same path in dae:

```shell
export DAE_EXTERNAL_POLICY_SOCKET=/run/dae/sing-box.sock
```

### socket_mode

Unix permission mode for the control socket, expressed as an integer. The
default is `384`, which is decimal `0600`. World-writable modes are rejected.

### producer_uid

Expected effective UID of the dae process. The default is the effective UID of
sing-box. Connections from a different UID are rejected through
`SO_PEERCRED`.

### output_mark

Socket mark applied to sing-box DNS, outbound, and transparent UDP reply
sockets. The default is `0x100`.

It must equal dae's effective `so_mark_from_dae`; otherwise sing-box traffic can
be captured recursively. A sing-box instance can register only one
auto-redirect output mark, so do not combine this inbound with another TUN or
auto-redirect datapath.

### metadata_timeout

Timeout for one original-tuple metadata lookup from dae. The default is `1s`.
A missing tuple is allowed; a protocol or transport error closes the new flow.

### UDP NAT fields

See [UDP NAT Fields](/configuration/shared/udp-nat/).

## dae process configuration

The processes must share a network namespace. Configure dae with the matching
mark and the expected sing-box UID:

```shell
# dae configuration
global {
  wan_interface: auto
  so_mark_from_dae: 0x100
}

# dae service environment
DAE_EXTERNAL_POLICY_SOCKET=/run/dae/sing-box.sock
DAE_EXTERNAL_POLICY_UID=0
```

In this mode sing-box is the sole userspace policy authority. dae forces
captured TCP and UDP flows to the transferred listeners and does not run its
own DNS listener, sniffing, or userspace route matcher.

The control channel carries only listener descriptors and tuple metadata;
application payload stays on the transferred kernel sockets.
