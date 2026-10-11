# xray.js 使用说明

一个纯 Node.js 的 Xray 一键部署脚本：单文件、零依赖，通过环境变量配置，自动下载 Xray 并生成配置和订阅链接。

## 1. 简介

`xray.js` 只使用 Node.js 内置模块，不需要 `npm install`、`openssl`、`unzip`、`curl`。运行后它会依次完成：

1. 解析环境变量，校验各协议的模式组合。
2. 准备 TLS 证书（可信证书或自签证书）。
3. 下载 Xray（以及按需下载 `cloudflared`、`komari-agent`）。
4. 生成 Xray 配置并做 `run -test` 检查。
5. 输出节点链接、base64 订阅和订阅地址。
6. 前台运行 Xray，脚本退出时一并结束所有子进程。

**运行要求**

- Node.js 16 及以上
- Linux，架构为 amd64 或 arm64
- 能访问 GitHub（下载二进制）和 `one.one.one.one`（探测公网 IP）

## 2. 支持的协议

| 协议 | 变量 | 可用模式 | 说明 |
| --- | --- | --- | --- |
| VLESS | `VLESS_MODE` | ws / cloudflare / 端口 / 回落协议 | 作为 Reality 链头时自动启用 `xtls-rprx-vision` 流控 |
| VMess | `VMESS_MODE` | ws / cloudflare / 端口 | 不能作为回落发起方 |
| Trojan | `TROJAN_MODE` | ws / cloudflare / 端口 / 回落协议 | 可回落 |
| Shadowsocks | `SHADOWSOCKS_MODE` | ws / cloudflare / 端口 | 加密方式 `aes-256-gcm`，不能回落 |
| Hysteria2 | `HYSTERIA2_MODE` | 仅数字端口（UDP） | 使用 TLS 证书，ALPN 为 h3 |
| Mixed | `MIXED_MODE` | 仅数字端口（TCP） | SOCKS5 + HTTP，账号 `UUID`，密码为 UUID |
| WireGuard | `WIREGUARD_MODE` | 仅数字端口（UDP） | 客户端地址 `10.0.0.2/32`，同时输出 wg-quick 配置 |

Hysteria2、Mixed、WireGuard 不参与回落链，也不使用 ws / cloudflare。

## 3. 快速开始

```bash
# 最简单：VLESS + Reality，监听 8443
VLESS_MODE=8443 node xray.js

# ws 模式，使用域名和证书（证书放在脚本同目录）
PORT=443 CERT_HOST=example.com VLESS_MODE=ws TROJAN_MODE=ws node xray.js

# Cloudflare 临时隧道，不需要域名和 Token
VLESS_MODE=cloudflare CLOUDFLARE_TUNNEL_TOKEN=try node xray.js
```

把环境变量写进启动命令即可。脚本启动后会把当前 UUID 写回自己的 `UUID:` 配置行，下次不带 `UUID` 变量运行也会沿用。

## 4. 环境变量

| 变量 | 说明 |
| --- | --- |
| `NAME` | 节点名称，用作链接的备注 |
| `UUID` | 用户 ID，同时是 Trojan / SS / Hysteria2 / Mixed 的密码。留空则自动生成并写回脚本 |
| `PORT` | ws / cloudflare 前置入口的端口；留空时默认 8000。只填 `PORT` 不选模式时，只提供订阅服务 |
| `VLESS_MODE` 等 | 各协议的模式，见下一节 |
| `HYSTERIA2_MODE` | Hysteria2 的 UDP 端口 |
| `MIXED_MODE` | Mixed 的 TCP 端口 |
| `WIREGUARD_MODE` | WireGuard 的 UDP 端口 |
| `CERT_HOST` | 域名或 IPv4，用于证书、链接地址和转发非订阅路径 |
| `CLOUDFLARE_TUNNEL_TOKEN` | cloudflare 模式的隧道 Token；填 `try` 使用临时隧道 |
| `CLOUDFLARE_IP` | cloudflare 链接中连接的地址（例如优选 IP）；留空则连隧道域名 |
| `KOMARI_ENDPOINT` / `KOMARI_TOKEN` | 两者都填才启用 Komari 探针 |

## 5. 模式语法

每个协议的 `*_MODE` 可以用逗号分隔，最多包含**一个前置模式**和**一个 Reality 项**，顺序随意。

| 取值 | 含义 |
| --- | --- |
| `ws` | WebSocket + TLS，经 `PORT` 前置入口接入 |
| `cloudflare` | WebSocket，经 Cloudflare 隧道回源，Xray 端是明文 |
| 数字（如 `8443`） | Reality，监听该端口 |
| 协议名（如 `trojan`） | Reality 回落：未通过认证的流量回落到该协议，仅 VLESS 和 Trojan 可用 |

**组合示例**

```bash
# VLESS 同时跑 ws 和 Reality(8443)，Trojan 只跑 ws
PORT=443 CERT_HOST=example.com VLESS_MODE=ws,8443 TROJAN_MODE=ws node xray.js

# VLESS Reality 回落到 Trojan，链在 8443 结束；两者同时还走 ws
PORT=443 VLESS_MODE=ws,trojan TROJAN_MODE=ws,8443 node xray.js

# 四个协议全开，ws 与 Reality 各自独立
VLESS_MODE=ws,8001 VMESS_MODE=ws TROJAN_MODE=ws,8002 SHADOWSOCKS_MODE=ws,8003 node xray.js
```

**规则与限制**

- 所有使用 ws / cloudflare 的协议必须选**同一种**，因为它们共用 `PORT` 前置入口。
- 一个协议最多属于一条 Reality 链，也最多只能被一个协议回落到。
- 回落链必须以带数字端口的协议结尾，链的对外端口取链尾的端口。
- 回落环（A 回落 B，B 又回落 A）会被检测并报错。
- 同一协议同时开两种模式时，输出两条链接，节点名加后缀 `-reality` 和 `-ws`（cloudflare 模式下为 `-cloudflare`）。

## 6. ws 与 cloudflare 的区别

两者传输方式相同（WebSocket，按路径分发），区别在流量如何到达服务器。

|  | `ws` | `cloudflare` |
| --- | --- | --- |
| 链路 | 客户端直连服务器 IP:PORT | 客户端 → Cloudflare 边缘 → cloudflared 隧道 → 本机 |
| TLS | Xray 自己终结，用 `CERT_HOST` 证书或自签 | Cloudflare 终结，Xray 收明文 |
| 是否需要开放入站端口 | 需要 | 不需要，cloudflared 主动外连 |
| 服务器 IP | 暴露在链接中 | 隐藏在 Cloudflare 后面 |
| 域名与证书 | 有域名和可信证书体验最好，也可只用 IP | 不需要证书；固定隧道需要 Token |
| 与 Reality 共用端口 | 可以 | 不可以 |

**选择建议**：没有公网入站端口或想隐藏 IP 时用 `cloudflare`；有公网 IP、追求低延迟时用 `ws`。

> ws 与 cloudflare 目前不能在同一次运行中同时使用，也不能共用同一个端口。

## 7. 端口共用（ws 与 Reality）

当 `PORT` 与某条 Reality 链的端口**相同**且为 ws 模式时，脚本自动让两者共用该端口：

```bash
PORT=443 CERT_HOST=example.com VLESS_MODE=ws,443 TROJAN_MODE=ws node xray.js
```

工作方式：

1. Reality 监听 443。
2. 带有效 Reality 认证的客户端进入 VLESS（或回落链）。
3. 其它 TLS 流量转给本机前置入口，使用 `CERT_HOST` 的证书终结 TLS。
4. 前置入口按路径分发：`/UUID-vless` 等进入对应 ws 入站，其余请求回落到内置 HTTP 服务。

此时 Reality 的伪装目标和 SNI 都是你自己的域名，链接里的 `sni` 会自动对应。cloudflare 模式不支持共用端口。

## 8. TLS 证书

脚本**不申请证书**。

- **可信证书**：`CERT_HOST` 为域名，并且脚本目录下有 `<CERT_HOST>.crt` 和 `<CERT_HOST>.key`。脚本会校验私钥是否配对、是否在有效期内、是否包含该域名，以及证书链能否落在系统信任的根证书上。通过则直接使用，客户端无需跳过校验。
- **自签证书**：不满足上述条件时，自动生成 RSA 2048、有效期 10 年的自签证书，保存在 `.selfsigned/` 目录，剩余有效期超过 30 天时会复用，避免重启后哈希变化。链接中通过 `pcs` 参数固定证书哈希。
- 使用自签证书时，Shadowsocks 的 ws 节点（v2ray-plugin 无法跳过校验）不会输出链接。

## 9. 订阅与内置 HTTP 服务

启用前置入口时，脚本内置一个 HTTP 服务，通过 abstract unix socket 接入，不占 TCP 端口：

- `GET /<UUID>` 返回 base64 订阅。
- 其它路径：如果 `PORT` 与 `CERT_HOST` 都已设置，转发到 `CERT_HOST:80`；否则返回 404。

订阅地址：

- ws 模式：`https://<地址>:<PORT>/<UUID>`
- cloudflare 模式：`https://<隧道域名>/<UUID>`
- 只填 `PORT`：`http://<地址>:<PORT>/<UUID>`（明文）

启动日志还会直接打印每行一条的节点链接和合并后的 base64 订阅。链接中的地址规则：`CERT_HOST` 填 IP 则直接使用；填域名且解析结果包含本机公网 IP 则使用域名；否则使用探测到的公网 IPv4。

## 10. Cloudflare 隧道

- `CLOUDFLARE_TUNNEL_TOKEN=try`：使用临时隧道，每次启动域名都会变，适合测试。
- 填真实 Token：运行固定隧道。隧道需要配置一个**不含 `*` 的 Public hostname**，Service 为 `http://localhost:端口`，脚本会从 cloudflared 日志读取域名和回源端口。
- 链接连接 `CLOUDFLARE_IP:443`（未设置则连隧道域名）。

## 11. Komari 探针

`KOMARI_ENDPOINT` 和 `KOMARI_TOKEN` 都填写才启用。有代理协议时，探针在后台运行；没有任何代理协议时，脚本只作为探针的启动脚本，前台运行。凭据通过环境变量只传给探针进程。

## 12. 内置行为

**路由规则**

- 私有 IP 直连。
- 屏蔽 `geosite:cn`、`geosite:category-ads-all` 和 `geoip:cn`。
- 服务器没有 IPv6 出口时，屏蔽 IPv6 目标，让客户端立即回退到 IPv4。

**密钥**

Reality 和 WireGuard 的密钥由 UUID 派生，同一个 UUID 永远得到同一组密钥，不落盘。

**Reality 参数**

默认伪装目标为 `www.iij.ad.jp:443`，short id 为 `cdcf853c`。

**内存**

Go 子进程设置了较低的 `GOGC`，在容器有内存限制时还会设置 `GOMEMLIMIT`。

**内部端口**

Shadowsocks 入站不支持 unix socket，会占用本机 TCP 端口 40004（Reality 回落链）和 40005（ws 入口），请不要把这两个端口用作监听端口。

## 13. 文件与目录

都在脚本所在目录：

| 路径 | 说明 |
| --- | --- |
| `xray/` | Xray 二进制、`config.json`（权限 600）、geo 数据 |
| `cloudflared`、`cloudflared.log` | cloudflare 模式的二进制和日志 |
| `komari-agent`、`komari-agent.log` | 探针二进制和日志 |
| `.selfsigned/` | 自签证书和私钥 |
| `<CERT_HOST>.crt` / `.key` | 你提供的可信证书 |

## 14. 常见问题

**启动时报 `Port N is used more than once`** 每条 Reality 链、`PORT` 前置入口和 `MIXED_MODE` 必须使用不同的 TCP 端口。要共用，请让 `PORT` 与 Reality 端口相同并使用 ws 模式。

**报 `must use the same mode`** ws 和 cloudflare 不能混用，所有前置协议要选同一种。

**报 `part of a fallback loop`** 回落关系成环了，需要有一个没有被任何协议回落到的链头。

**客户端连 ws 提示证书错误** 没有可信证书，使用的是自签证书。请导入带 `pcs` 的链接，或者放置可信证书。

**订阅里缺少某个节点** 看启动日志中的 `[MODE]` 提示，常见原因是 cloudflare 模式没有读到隧道域名，或者自签证书下的 Shadowsocks ws 节点被跳过。

## 15. 安全提示

- 脚本每次启动都会**改写自己**来保存 UUID，请不要把含有真实 UUID 的脚本随意分享。
- 日志会打印 **Reality 私钥**，也包含完整的节点链接和订阅内容，注意日志的保管范围。
- Xray、cloudflared、komari-agent 都下载 `latest` 版本，**没有校验和或签名校验**，相当于信任 GitHub 的发布文件。
- cloudflare 模式下前置入口监听 `::` 且是明文，如果端口对公网开放，别人可以绕过 Cloudflare 直连。建议用防火墙限制只允许本机访问。
- Mixed 模式使用用户名 `UUID`，密码为 UUID，请避免把该端口无防护地暴露。
