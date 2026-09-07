!!! quote "自定义 Linux 构建"

    使用 `with_dae` 构建标签。该入站把独立的 dae 捕获模块直接嵌入 sing-box 进程，不启动 dae 守护进程，也不使用 IPC。

# dae eBPF

`dae` 入站替代 TUN/redirect 捕获层；DNS、FakeIP、流量嗅探、路由规则和出站仍全部由 sing-box 负责。

```text
Linux TC/cgroup eBPF -> 透明 TCP/UDP 监听器 -> sing-box 路由 -> sing-box 出站
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
  "require_process_metadata": true,
  "bpf_conn_state_map_size": 262144,

  "udp_timeout": "5m",
  "udp_mapping": "endpoint_independent",
  "udp_filtering": "endpoint_independent",
  "udp_nat_max": 16384
}
```

必须至少配置一个 LAN 或 WAN 接口。进程必须以 root 身份运行，内核需要支持 cgroup v2 以及所需的 TC/eBPF 功能。

### 捕获字段

#### lan_interface

承载转发客户端流量的接口，适用于路由器或出口节点的 LAN 侧。

#### wan_interface

承载本机生成流量和 WAN 侧流量的接口。`auto` 会在捕获运行时启动时解析；默认接口变化后需要重启 sing-box，让模块重新附加到新接口。

#### tproxy_port

内部透明监听端口，默认值为 `12345`。

#### output_mark

应用于 sing-box DNS、出站和透明 UDP 回复套接字的标记，防止流量被重复捕获。默认值为 `0x100`。`dae` 不能与另一个自动重定向捕获所有者同时使用，例如启用了 `auto_redirect` 的 TUN 入站。

#### auto_config_kernel_parameter

允许模块临时设置所选拓扑需要的转发和接口 sysctl，并在关闭时恢复原值。

#### require_process_metadata

如果无法附加 WAN 进程元数据所需的 cgroup 钩子，则启动失败。这些元数据用于 `process_name`、`process_path` 和 `user_id` 规则。禁用后允许捕获继续启动，但相关匹配会安全降级。

#### bpf_conn_state_map_size

eBPF 连接状态表的最大条目数。默认值为 `262144`，最小值为 `1024`。

### UDP NAT 字段

参阅 [UDP NAT 字段](/configuration/shared/udp-nat/)。

### 生命周期与重载

模块只拥有一组监听器，sing-box 也只运行一组接收循环。使用相同标签和完全相同捕获设置替换入站时，只切换当前 sing-box 处理器，不复制套接字，也不启动第二套 eBPF 数据面。第二个标签会被拒绝。修改接口、端口、标记、内核设置、元数据要求或状态表大小时需要重启进程。

如果 sing-box 未正常关闭，下一次启动不会猜测并删除主机状态。确认旧的 sing-box 进程已经退出后，执行：

```bash
sudo sing-box tools dae cleanup-stale
```

清理前会核对所有权日志、进程和启动标识、网络命名空间标识、链路令牌、TC 槽位以及 BPF 程序 ID。

如果内核捕获拆卸返回错误，sing-box 会有意保留输出标记租约，避免残留钩子重新捕获自身流量。此时应清理日志记录的残留状态并重启进程，不要在捕获所有权不明确时继续运行。

### 构建

```bash
go build -tags "with_dae,$(cat release/DEFAULT_BUILD_TAGS)" \
  -ldflags "$(cat release/LDFLAGS)" ./cmd/sing-box
```

在独立模块合并到上游或发布标签之前，本分支通过 `replace` 指令把标准模块路径固定到 `wignerStan/dae`。
