---
icon: material/new-box
---

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [listen_port](#listen_port)  
    :material-plus: [ssh_server](#ssh_server)  
    :material-plus: [taildrop_directory](#taildrop_directory)

!!! quote "sing-box 1.13.0 中的更改"

    :material-plus: [relay_server_port](#relay_server_port)  
    :material-plus: [relay_server_static_endpoints](#relay_server_static_endpoints)  
    :material-plus: [system_interface](#system_interface)  
    :material-plus: [system_interface_name](#system_interface_name)  
    :material-plus: [system_interface_mtu](#system_interface_mtu)  
    :material-plus: [advertise_tags](#advertise_tags)

!!! question "自 sing-box 1.12.0 起"

### 结构

```json
{
  "type": "tailscale",
  "tag": "ts-ep",
  "state_directory": "",
  "auth_key": "",
  "control_url": "",
  "ephemeral": false,
  "hostname": "",
  "accept_routes": false,
  "exit_node": "",
  "exit_node_allow_lan_access": false,
  "advertise_routes": [],
  "advertise_exit_node": false,
  "advertise_tags": [],
  "listen_port": 0,
  "relay_server_port": 0,
  "relay_server_static_endpoints": [],
  "system_interface": false,
  "system_interface_name": "",
  "system_interface_mtu": 0,
  "udp_timeout": "5m",
  "ssh_server": false,
  "taildrop_directory": "",

  ... // 拨号字段
}
```

### 字段

#### state_directory

存储 Tailscale 状态的目录。

默认使用 `tailscale`。

示例：`$HOME/.tailscale`

同时运行多个 Tailscale 端点时，应为每个端点使用独立的状态目录（并最好使用
不同的主机名）。如果认证密钥的 tailnet 策略允许复用，同一个可复用密钥即可
分别授权这些实例。

#### auth_key

!!! note

    认证密钥不是必需的。默认情况下，sing-box 将记录登录 URL。

用于创建节点的认证密钥。如果节点已经创建（从之前存储的状态），则不使用此字段。

#### control_url

协调服务器 URL。

默认使用 `https://controlplane.tailscale.com`。

#### ephemeral

指示实例是否应注册为临时节点 (https://tailscale.com/s/ephemeral-nodes)。

#### hostname

节点的主机名。

默认使用系统主机名。

!!! question "自 sing-box 1.14.0 起"

    在 iOS、tvOS 和 Android 上，默认使用设备名称。

示例：`localhost`

#### accept_routes

指示节点是否应接受其他节点通告的路由。

#### exit_node

要使用的出口节点名称或 IP 地址。

#### exit_node_allow_lan_access

!!! note

    当出口节点没有相应的通告路由时，即使设置了 `exit_node_allow_lan_access`，私有流量也无法路由到出口节点。

指示本地可访问的子网应该直接路由还是通过出口节点路由。

#### advertise_routes

通告到 Tailscale 网络的 CIDR 前缀，作为可通过当前节点访问的路由。

示例：`["192.168.1.1/24"]`

#### advertise_exit_node

指示节点是否应将自己通告为出口节点。

#### advertise_tags

!!! question "自 sing-box 1.13.0 起"

为此节点通告的标签，用于 ACL 执行。

示例：`["tag:server"]`

#### listen_port

!!! question "自 sing-box 1.14.0 起"

监听 WireGuard 和点对点流量的 UDP 端口。

默认自动选择端口。

#### relay_server_port

!!! question "自 sing-box 1.13.0 起"

监听来自其他 Tailscale 节点的中继连接的端口。

#### relay_server_static_endpoints

!!! question "自 sing-box 1.13.0 起"

为中继服务器通告的静态端点。

#### system_interface

!!! question "自 sing-box 1.13.0 起"

为 Tailscale 创建系统 TUN 接口。

在此模式下，主机 TUN 是唯一的通用数据平面。不会创建内嵌 gVisor 网络栈，端点也不会暴露 `tun.Port` 流量路径。`ssh_server` 与 Taildrop 当前不可与 `system_interface` 同时使用。

在 Darwin 上选择 `exit_node` 后，sing-box 还会为此 TUN 维护按接口限定的
IPv4/IPv6 默认路由。路由使用本机 Tailscale 地址作为接口地址，仅供绑定到
`system_interface` 的套接字使用；Tailscale 控制面套接字仍走普通网络接口。
当某个地址族尚未获得 Tailscale 地址时会暂不安装对应路由，因此仅有 IPv4
的网络仍可正常工作。链路切换期间，已安装的地址族路由只会在有限的宽限期
内保留；如果系统 TUN 的接口索引发生变化，则会立即移除旧路由。切换退出
节点时，首次确定性的路由同步完成前不会返回成功；临时的地址/接口竞争会
使用有上限的指数退避重试，而永久错误会直接返回给调用方。

按接口路由会携带与 TUN 相同且锁定的 MTU 指标。这在 Darwin 上是必要的：
否则未限定的路由缓存可能继承物理网卡的 1500 字节 TCP MSS，向配置的
TUN MTU（默认 1280）写入过大的数据包。若发现旧路由已经存在，sing-box 会先
通过 `RTM_CHANGE` 修复后再接管。路由同步独立于 Tailscale 重配置回调，并会
在端点运行期间重试失败的同步。路由选择依赖 `IP_BOUND_IF`/`bind_interface`；
仅绑定源地址并不等价，仍可能使用物理路由的 MSS。

从外部按接口路由监视器迁移时，应先停止该监视器，再启用此模式，避免两个
路由所有者同时改写同一接口。端点接管后应保持外部监视器禁用。

同一个 sing-box 进程中只允许一个活动的 Tailscale 端点。嵌入式 Tailscale
服务器使用的 `netns` 与网络监视钩子是进程全局状态；sing-box 会拒绝第二个
端点，而不是允许它覆盖或清除第一个端点的钩子。不同进程也应使用不同的
系统接口，并且不得同时管理同一组按接口路由。

#### system_interface_name

!!! question "自 sing-box 1.13.0 起"

自定义 TUN 接口名。默认使用 `tailscale`（macOS 上为 `utun`）。

#### system_interface_mtu

!!! question "自 sing-box 1.13.0 起"

覆盖 TUN 的 MTU。默认使用 Tailscale 自己的 MTU。

#### udp_timeout

UDP NAT 过期时间。

默认使用 `5m`。

#### ssh_server

!!! question "自 sing-box 1.14.0 起"

在 tailnet 的 TCP 22 端口上运行 Tailscale SSH 服务器。

访问控制由 Tailscale 管理控制台中的 SSH ACL 决定，它将每个连接映射到一个本地用户。该用户如何解析、以及允许哪些用户，取决于平台：

- **Linux** 和 **macOS**：从系统用户数据库解析用户。要切换到 sing-box 运行身份以外的用户需要以 root 运行；非 root 时，会话仅限于当前用户。
- **Windows**：在命令行客户端中，会话以 sing-box 进程的身份运行；映射的用户不会被模拟，因此映射到其他本地账户的会话将被拒绝。在图形客户端中没有此限制。
- **Android**：用户由应用解析，而非系统用户数据库。`root` 即超级用户（UID 0），`shell` 为 ADB shell 用户（UID 2000）；其他名称均作为已安装应用的包名解析，以该应用的 UID 运行，并使用其数据目录作为主目录，因此目标应用必须已安装。`termux` 是 `com.termux` 的快捷方式，`sing-box` 是应用自身包名的快捷方式；当 Termux 已安装时，`root` 和 `termux` 用户将加载 Termux 环境。以 sing-box 应用自身身份运行无需 root，其他用户则需要已授予的 root 权限；非 root 时，会话仅限于 sing-box 用户。
- **macOS**：SSH 服务器仅在独立版本中可用，且需要辅助服务；App Store 版本不支持。
- **iOS**：SSH 服务器仅在越狱版本中可用；App Store 和 TestFlight 版本不支持。
- **tvOS**：暂不支持。

对象格式：

```json
{
  "enabled": true,
  "disable_pty": false,
  "disable_sftp": false,
  "disable_forwarding": false
}
```

将 `ssh_server` 值设置为 `true` 等同于 `{ "enabled": true }`。

#### ssh_server.enabled

启用 SSH 服务器。

#### ssh_server.disable_pty

拒绝 PTY 分配请求。

#### ssh_server.disable_sftp

拒绝 SFTP 子系统。

#### ssh_server.disable_forwarding

拒绝本地和远程的 TCP 与 Unix 套接字转发，包括 SSH agent 转发。

#### taildrop_directory

!!! question "自 sing-box 1.14.0 起"

存储从 tailnet 对等节点接收到的文件的目录。

相对路径基于工作目录解析，与 [state_directory](#state_directory) 相同。

默认使用 `Taildrop`。

### 拨号字段

!!! note

    Tailscale 端点中的拨号字段仅控制它如何连接到控制平面，与实际连接无关。

参阅 [拨号字段](/zh/configuration/shared/dial/) 了解详情。

### 交互式认证

在 sing-box dashboard 或任意 sing-box 图形客户端的 `工具` > `端点` 中认证和管理 endpoint。
