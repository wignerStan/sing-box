!!! quote "自定义构建"

    仅支持 Linux。需要使用 `-tags with_dae` 构建。该入站在进程内直接嵌入 dae 的 eBPF 捕获运行时，不启动 dae 守护进程，也不使用 IPC。

# dae eBPF

`dae` 入站替代 TUN/redirect 捕获层，但 DNS、FakeIP、协议嗅探、路由、规则集与出站选择仍完全由 sing-box 负责。

```text
tc/cgroup eBPF -> 透明 TCP/UDP generation -> sing-box 路由 -> sing-box 出站
```

### 结构

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

必须至少配置一个 LAN 或 WAN 接口。接口值沿用 dae 的接口匹配语法。

### 字段

#### lan_interface

捕获这些接口的入站流量，适用于路由器/LAN 场景。

#### wan_interface

捕获这些接口上的本机出站流量。成功挂载所需 cgroup hook 时可获得进程元数据。

#### tproxy_port

内部透明监听端口。默认值：`12345`。

#### output_mark

应用到 sing-box DNS 与出站套接字的标记，用于避免被 dae 再次捕获。默认值：`0x100`。

一个 sing-box 进程只能使用一个 auto-redirect 输出标记；热重载期间多个 `dae` generation 可以复用同一标记。

#### auto_config_kernel_parameter

允许 dae 配置所需的转发与接口 sysctl。

#### bpf_conn_state_map_size

eBPF 连接状态表最大条目数。默认值：`262144`，最小值：`1024`。

### UDP NAT 字段

参阅 [UDP NAT 字段](/configuration/shared/udp-nat/)。

### 重载行为

捕获配置不变时，重载会复制并原子发布透明监听 generation。修改捕获接口、端口、输出标记、内核配置模式或 map 大小时，当前需要重启进程。

### 构建

```bash
go build -tags "with_dae,$(cat release/DEFAULT_BUILD_TAGS)" \
  -ldflags "$(cat release/LDFLAGS)" ./cmd/sing-box
```

当前 provider 固定导入 `go.mod` 中的 dae fork 修订版。公开的 `ebpfinbound` 接口保持策略无关；provider 实现仍暂时复用 dae 的兼容控制面，后续会继续做物理提取和精简。
