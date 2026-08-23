# dae

仅支持 Linux，不支持 Android。

`dae` 入站会接收由 dae TC/cgroup eBPF 数据面创建的透明 TCP/UDP 监听套接字，
随后使用 sing-box 原有的嗅探、DNS、FakeIP、路由和出站流程处理连接。

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

## 字段

### socket_path

必填。

sing-box 创建的 Unix `SOCK_SEQPACKET` 控制套接字绝对路径。应先启动该入站，
再启动 dae。

在 dae 中设置相同路径：

```shell
export DAE_EXTERNAL_POLICY_SOCKET=/run/dae/sing-box.sock
```

### socket_mode

控制套接字的 Unix 权限，以整数表示。默认值为 `384`，即八进制 `0600`。
配置为任何用户可写的模式会被拒绝。

### producer_uid

预期的 dae 进程有效 UID。默认值是 sing-box 的有效 UID。不同 UID 的连接会
通过 `SO_PEERCRED` 验证并被拒绝。

### output_mark

应用于 sing-box DNS、出站和透明 UDP 回复套接字的 mark，默认值为 `0x100`。

该值必须等于 dae 实际使用的 `so_mark_from_dae`，否则 sing-box 发出的流量可能
被递归捕获。一个 sing-box 实例只能注册一个 auto-redirect 输出 mark，因此不要
将该入站与其他 TUN 或 auto-redirect 数据面同时使用。

### metadata_timeout

从 dae 查询一次原始五元组元数据的超时时间，默认值为 `1s`。查不到五元组是
允许的；协议或传输错误会关闭新流。

### UDP NAT 字段

参阅 [UDP NAT 字段](/zh/configuration/shared/udp-nat/)。

## dae 进程配置

两个进程必须位于同一个网络命名空间。为 dae 配置一致的 mark 和预期的
sing-box UID：

```shell
# dae 配置
global {
  wan_interface: auto
  so_mark_from_dae: 0x100
}

# dae 服务环境变量
DAE_EXTERNAL_POLICY_SOCKET=/run/dae/sing-box.sock
DAE_EXTERNAL_POLICY_UID=0
```

在该模式下，sing-box 是唯一的用户态策略权威。dae 会将捕获的 TCP/UDP 流量
强制送入已交接的监听器，并停止自己的 DNS 监听器、嗅探和用户态路由匹配器。

控制通道只传输监听器描述符和五元组元数据；应用数据始终留在交接后的内核
套接字上。
