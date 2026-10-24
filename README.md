# Shadowsocks-Rust

OpenWrt 透明代理解决方案，基于 shadowsocks-rust，提供 LuCI 图形界面配置。

## 功能特性

- 🚀 基于 shadowsocks-rust 的高性能透明代理
- 🌐 支持 TCP/UDP 透明代理 (tproxy)
- 🔍 智能 DNS 分流（白名单域名走隧道，其余直连）
- 📋 ACL 规则支持（域名、IP 分流）
- 🖥️ LuCI 图形界面配置
- ⚡ 支持 SOCKS5 和 HTTP 代理
- 🔄 多服务器负载均衡
- 🛡️ 重放攻击防护

## 安装

### 方式一：IPK 安装包（推荐）

1. 在 OpenWrt 管理界面：`系统` → `软件包` → `上传安装`
2. 或通过命令行安装：

```bash
scp shadowsocks-rust_*.ipk root@router:/tmp/
ssh root@router "opkg install /tmp/shadowsocks-rust_*.ipk /tmp/luci-app-shadowsocks-rust_*.ipk"
```

### 方式二：手动安装

```bash
# 1. 安装 sslocal：使用 OpenWrt 的 shadowsocks-rust-sslocal 包，
#    或把官方 Release 中的 sslocal 复制到 /usr/bin/sslocal
ssh root@router "opkg install shadowsocks-rust-sslocal"

# 2. 复制 LuCI 界面文件
scp -r luci-app-shadowsocks-rust/htdocs/* root@router:/www/
scp -r luci-app-shadowsocks-rust/root/* root@router:/

# 3. 复制后端配置和脚本文件
scp -r shadowsocks-rust/files/* root@router:/

# 4. 启用服务
ssh root@router "/etc/init.d/shadowsocks-rust enable"
```

### 方式三：编译 ipk（OpenWrt 源码 / SDK）

仓库按 LuCI 插件的标准结构组织，目录与包的对应关系：

| 目录 | 软件包 | 说明 |
|------|--------|------|
| `luci-app-shadowsocks-rust/` | `luci-app-shadowsocks-rust` | LuCI 界面（`luci.mk`） |
| `shadowsocks-rust/` | `shadowsocks-rust` | TProxy 服务（UCI 配置、ucode 防火墙模板）；同时编译 shadowsocks-rust 的 sslocal 等子包（`shadowsocks-rust-sslocal` 等） |

把这两个目录放入 feed 或 `package/` 下，然后：

```bash
make package/shadowsocks-rust/compile V=s
make package/luci-app-shadowsocks-rust/compile V=s
```

### 依赖安装

Shadowsocks-Rust 依赖 `nftables`、`ucode`（用于渲染防火墙规则）和 `sslocal`，安装包时会自动拉取；手动安装时请确保已装好：

```bash
opkg update
opkg install nftables kmod-nft-tproxy ucode ucode-mod-fs ucode-mod-uci
```

## 配置使用

### 基础配置

1. 打开 LuCI 界面：`服务` → `Shadowsocks-Rust` → `Basic Settings`
2. 在「Service Settings」中配置：
   - **启用**：开启服务
   - **远程 DNS**：国外 DNS 服务器（如 `1.1.1.1`，Cloudflare DNS），用于解析「代理域名」列表里的域名，查询会走隧道
   - **透明代理端口**：默认 `60080`
   - **DNS 端口**：默认 `5300`
   - **SOCKS5 端口**：可选，设为 `0` 禁用
   - **HTTP 代理端口**：可选，设为 `0` 禁用

> 💡 本地 DNS（非代理域名）由 dnsmasq 按照 `/etc/config/dhcp` 里的配置解析，Shadowsocks-Rust 不再接管 dnsmasq 的上游设置。

### 节点配置（Nodes 标签页）

> 💡 LuCI 分为三个页面：**Basic Settings**（包含 Service Settings 和 Advanced Settings）、**Nodes**、**Rules**

1. 在「Nodes」标签页添加 Shadowsocks 节点
2. 填写节点信息：
   - **Server**：远程节点的地址，支持 IPv4、IPv6 和域名
   - **端口**：服务器端口
   - **密码**：连接密码
   - **加密方式**：推荐 `aes-256-gcm` 或 `chacha20-ietf-poly1305`
   - **Plugin**：可选，目前仅支持 `obfs-local`（simple-obfs）
   - **Plugin Options**：插件参数，如 `obfs=http;obfs-host=www.bing.com`

> 💡 远程节点在 UCI 里是 `config node` 段（地址选项仍叫 `server`），这样和本机运行的 shadowsocks 服务端区分得开

> 💡 建议同时配置 IPv4 和 IPv6 服务器。sslocal 会在多个节点之间做负载均衡，并按延迟选择可用节点

> ⚠️ 加密方式下拉框只列出当前 sslocal 二进制真正支持的方式。`bf-cfb`、`salsa20`（上游已移除）、`aes-192-gcm`（上游没有这个）、`xchacha20-ietf-poly1305`（需要非默认的 aead-cipher-extra 特性）会让 sslocal 直接拒绝启动，因此不在列表中。如果之前用的是这些方式，升级后需要手动改成一个受支持的方式

#### 使用 obfs 混淆（simple-obfs）

obfs 不是加密方式，而是 SIP003 传输插件，目前仅支持 simple-obfs 的客户端 `obfs-local`。除了上面的加密参数外，还需要：

1. 设备上安装插件程序，提供 `/usr/bin/obfs-local`
2. 服务器端同时运行 `obfs-server`，参数与客户端对应
3. 在节点配置里把 Plugin 选为 `obfs-local`，并填写 Plugin Options

| 配置项 | 示例值 |
|--------|--------|
| Plugin | `obfs-local` |
| Plugin Options | `obfs=http;obfs-host=www.bing.com` |

`Plugin Options` 直接传给 simple-obfs，常用参数：

- `obfs=http` 或 `obfs=tls`：混淆方式
- `obfs-host=www.bing.com`：伪装域名，`http` 模式下建议填

生成的 `config.json` 会带上对应字段：

```json
{
  "server": "1.2.3.4",
  "server_port": 8388,
  "password": "password",
  "method": "aes-256-gcm",
  "plugin": "obfs-local",
  "plugin_opts": "obfs=http;obfs-host=www.bing.com"
}
```

> ⚠️ 插件没安装时启动日志会提示 `plugin obfs-local is not installed`；手动写了其它插件名会被忽略并记录 `unsupported plugin ...` 错误
>
> ⚠️ simple-obfs 只处理 TCP，使用 obfs 时该服务器的 UDP 流量（UDP 转发、UDP DNS）无法通过插件，会直连服务器并失败

### 高级设置

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| worker_count | 工作线程数，**应设为 CPU 核数** | 4 |
| client_cache_size | DNS 缓存大小 | 64 |
| no_delay | TCP_NODELAY，关掉 Nagle 降延迟 | 启用 |
| keep_alive | TCP 保活时间(秒) | 15 |
| nofile | 最大文件描述符 | 10240 |
| fast_open | TCP Fast Open | 禁用 |
| mptcp | 多路径 TCP | 禁用 |

> 💡 `worker_count` 设得比 CPU 核数大只会浪费内存和调度开销，不会提升吞吐。调优细节见 [性能调优](#性能调优)

> 💡 强制代理、绕过的 IP 和域名不在这里配置，而是在 Rules 页面，见下文「自定义分流规则」

### 应用配置

配置完成后点击「保存并应用」，服务将自动启动。

## 配置文件说明

所有配置文件位于 `/etc/shadowsocks-rust/` 目录：

| 文件 | 说明 |
|------|------|
| `/etc/config/shadowsocks-rust` | UCI 配置（LuCI 页面读写的就是这个文件） |
| `/etc/shadowsocks-rust/shadowsocks-rust-redir.acl` | sslocal 透明代理的 ACL 规则 |
| `/etc/shadowsocks-rust/log4rs.yml` | sslocal 日志配置，启动时复制到 `/var/shadowsocks-rust/` |
| `/var/shadowsocks-rust/config.json` | 运行时生成的 sslocal 配置（在 /var 下，避免写 flash） |
| `/var/shadowsocks-rust/shadowsocks-rust.nft` | 运行时渲染出的 nftables 规则 |
| `/usr/share/shadowsocks-rust/ss-rules/` | nftables 规则模板（ucode：`rules.uc`、`set.uc`、`chain.uc`） |

## 服务管理

```bash
# 启动服务
/etc/init.d/shadowsocks-rust start

# 停止服务
/etc/init.d/shadowsocks-rust stop

# 重启服务
/etc/init.d/shadowsocks-rust restart

# 查看服务状态
/etc/init.d/shadowsocks-rust status

# 开机自启
/etc/init.d/shadowsocks-rust enable

# 禁用自启
/etc/init.d/shadowsocks-rust disable
```

## 性能调优

下面每一条都对着 shadowsocks-rust 源码核对过，标注了字段所在位置，避免调到不存在或不生效的参数。

### 先说三个容易踩空的地方

**1. 收发缓冲区不能写在 config.json 里**

`inbound_send_buffer_size` / `inbound_recv_buffer_size` / `outbound_send_buffer_size` / `outbound_recv_buffer_size` 这四个只存在于内部的 `ConnectOpts`/`AcceptOpts`，**从来不从 `SSConfig` 赋值**——写进 config.json 会被静默忽略。它们只是命令行参数：

```bash
ssserver -c config.json --outbound-recv-buffer-size 4194304
```

**但通常不该设。** 显式 `setsockopt(SO_RCVBUF/SO_SNDBUF)` 会**关掉内核的接收缓冲自动调整**（`tcp_moderate_rcvbuf`）。只要 `net.core.rmem_max` / `net.ipv4.tcp_rmem` 上限给够，内核会按实际带宽时延积自动伸缩，比手工拍一个固定值更准。手工设小了反而会成为跨境长肥管道的瓶颈。调大内核上限，别动 socket 选项。

**2. `timeout` 是连接超时，不是空闲超时**

源码 `crates/shadowsocks/src/config.rs` 里注释写的是 `Handshake timeout (connect)`，运行时只包住 `connect_server_with_opts`。所以默认的 `15` 是合适的，**不要往大调**——调成 300 不会让长连接更稳，只会让故障服务器的切换从 15 秒变成 5 分钟。空闲连接的回收由 `keep_alive` 和 `udp_timeout` 负责。

**3. `worker_count` 设得比 CPU 核数大只有坏处**

源码 `src/config.rs` 注释：`Multithread runtime worker count, CPU count if not configured`。**留空即按核数自适应**，这是最优解。设成核数的十几倍不会提升吞吐（单机吞吐上限由核数决定），只会多出线程栈和调度开销：

| 场景 | 改动 | 效果 |
|------|------|------|
| 1 核 VPS | `worker_count: 16` → 移除 | 线程 16→1，RSS 约 11MB |
| 4 核路由器 | `worker_count: 64` → `4` | 线程 ~67→7，虚拟内存 209MB→28MB |

### 服务端 (ssserver) 推荐配置

```json
{
  "nofile": 32768,
  "udp_timeout": 300,
  "udp_max_associations": 2048,
  "no_delay": true,
  "keep_alive": 30,
  "runtime": { "mode": "multi_thread" }
}
```

| 配置项 | 作用 |
|--------|------|
| `no_delay: true` | 开 TCP_NODELAY 关掉 Nagle。默认 `false`，小包会被攒够或等 40ms 才发，视频分片请求和交互操作都会平白多一截延迟 |
| `keep_alive: 30` | 探测死连接，回收对端已消失的会话和 NAT 表项 |
| `udp_max_associations: 2048` | UDP(QUIC/视频)关联数上限。默认**无上限**，小内存机器需要兜底 |
| `runtime` 不写 `worker_count` | 按 CPU 核数自适应，见上 |

### 客户端 (sslocal / OpenWrt) 推荐配置

OpenWrt 侧通过 uci 配置，`/etc/init.d/shadowsocks-rust` 会套用到模板：

```bash
uci set shadowsocks-rust.global.worker_count=4     # = CPU 核数
uci set shadowsocks-rust.global.no_delay=1
uci commit shadowsocks-rust && /etc/init.d/shadowsocks-rust restart
```

`fast_open`（TCP Fast Open）默认关闭，建议保持——很多中间设备会丢弃带 TFO 数据的 SYN，导致首包重传，反而更慢。

### 系统参数

代理节点和路由器都建议：

```bash
# 跨境长肥管道: BBR 比 cubic 更能吃满带宽，且不会把缓冲区灌满
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq            # 路由器用 fq_codel

# 关键: 空闲后不要把拥塞窗口打回初始值
net.ipv4.tcp_slow_start_after_idle = 0

# 给足自动调整的上限（不要去设 socket 的 SO_RCVBUF）
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
```

`tcp_slow_start_after_idle = 0` 对看视频影响最直接：播放器缓冲满了就暂停拉流，几秒后再拉，此时拥塞窗口已被重置回初始值，每次恢复都要重新爬坡——表现就是码率反复降级、来回卡顿。

OpenWrt 上 BBR 模块通常有但没加载：

```bash
modprobe tcp_bbr
echo tcp_bbr > /etc/modules.d/99-tcp-bbr      # 开机自动加载
sysctl -n net.ipv4.tcp_available_congestion_control   # 确认出现 bbr
```

路由器用 `fq_codel` 而非 `fq`，治的是 bufferbloat：上传占满时交互流量被大流堵在队列里，是视频卡顿和游戏延迟飙升的主因。注意 `default_qdisc` **只对新建的 qdisc 生效**，已有接口要手动换：

```bash
for dev in pppoe-wan eth0 eth1; do tc qdisc replace dev $dev root fq_codel; done
tc qdisc show | grep -v noqueue      # 确认不再是 pfifo_fast
```

> 💡 如果上下行带宽已知，装 `sqm-scripts` 做限速整形（cake）效果比裸 fq_codel 更好，但需要填真实线路速率，填错反而限制带宽。

### 效果验证

```bash
# 线程数是否降下来
PID=$(pidof ssserver); ls /proc/$PID/task | wc -l

# 拥塞算法/qdisc 是否生效
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.tcp_slow_start_after_idle

# 实际连接用的拥塞算法
ss -tin | grep -o "bbr\|cubic" | sort | uniq -c
```

## 常见问题

### 安装后 LuCI 界面不显示

```bash
# 清除 LuCI 缓存
rm -rf /tmp/luci-*

# 刷新浏览器缓存 (Chrome: F12 → Network → Disable cache)
```

### 无法上网（DNS 问题）

首次配置时，如果服务器信息不正确，可能导致 DNS 无法解析。

解决方法：
1. 临时禁用 Shadowsocks-Rust：`/etc/init.d/shadowsocks-rust stop`
2. 修正服务器配置
3. 重新启动服务

### OpenWrt 版本要求

防火墙规则由 ucode 模板渲染，需要系统提供 `ucode` 相关包。CI 目前只针对 OpenWrt 22.03 构建，建议使用 22.03 及以上版本；21.x 上如果没有这些包，需要自行处理依赖。

```bash
opkg update
opkg install nftables kmod-nft-tproxy ucode ucode-mod-fs ucode-mod-uci
```

### IPv6 支持

- 如果本地网络支持 IPv6，建议配置 IPv6 服务器
- 某些域名仅解析 IPv6 地址，没有 IPv6 服务器可能无法访问
- 如果本地只有 IPv4，可以只使用 IPv4 服务器

### DNS 解析原理

```
[客户端] → [dnsmasq] ── 国内域名 → 默认上游 DNS（直连）
                  └─ 代理域名   → [Shadowsocks-Rust DNS(5300)] → 远程 DNS（走隧道）
                                                     └─ 解析到的 IP 写入 nft set，流量走代理
```

### 自定义分流规则

在 LuCI 的 `Rules` 页面配置，分为以下几组：

- **Policy**：默认策略
  - `Default for Source IPs`：未列入源 IP 列表的客户端，直连 / 检查目的地址 / 全部代理
  - `Default for Destinations`：未列入目的地址列表的流量，直连 / 代理
  - `Router Traffic`：路由器自身发出的连接，直连 / 检查目的地址 / 全部代理
- **Source Bypass / Source Forward / Source Check Destination**：按客户端源 IP/CIDR 区分，分别表示始终直连、始终代理、按目的地址判断
- **Proxy Domain**：代理域名，域名及其子域名的查询走隧道，解析到的 IP 加入代理 nft set
- **Bypass Domain**：绕过域名，直接解析，解析到的 IP 直连。同时出现在两个列表里时按绕过处理
- **Bypass Ipset / Proxy Ipset**：绕过 / 强制代理的 IP/CIDR

## 许可证

GNU General Public License v3.0