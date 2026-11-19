# argo-rs

参考官方 `cloudflared` 源码（2026.11.1）用 Rust 重写的精简版 Cloudflare Tunnel 客户端。目标：**用官方 token 连上 Cloudflare edge、完成注册、保持连接、优雅注销**，本地网页配置路由端口，支持基础 HTTP / WebSocket 数据转发，并实现 **QUIC 优先、HTTP/2 回退** 的双传输（`--protocol auto`，默认）。

## 已验证（用真实 token 实测通过）

```
token 解析成功 tunnel_id=97425bba-... account_tag=0de1bc7f...
edge 地址发现完成 count=40
连接 Cloudflare edge (QUIC) edge=198.41.192.107:7844
隧道注册成功 location=lax08 connection_id=32987a1e...
收到 Ctrl-C，正在注销隧道连接
注销请求已送达，edge 随即断开连接
```

- Cap'n Proto RPC 与官方 edge 完全互通（bootstrap → `registerConnection` → `unregisterConnection`）
- QUIC 传输、SRV edge 发现、TLS（含内置 Cloudflare 根证书）均正常
- 配置网页 GET/POST/落盘/热更新验证通过

### 端到端数据面实测（真实公网域名）

绑定域名 `test.evec.us.ci`，本地 `127.0.0.1:8080` 起测试服务，`routes.json` 配
`test.evec.us.ci → 8080`。隧道未启动时域名返回 `530 / error 1033`（经典 Tunnel 离线）；
启动 argo-rs 后：

```
$ curl http://test.evec.us.ci/api/users?id=42
ARGO_RS_E2E_OK path=/api/users?id=42 host=test.evec.us.ci   [HTTP 200]
```

根路径、带 query、多级路径多次请求均 200，Host 头与路径正确透传。edge 偶尔主动发来的
反向 RPC 流（如 `updateLocalConfiguration`，签名 `52 BB 82 5C DB 65`）会被识别并安静关闭，
不产生错误日志。

### WebSocket 实测（已通过）

识别 `ConnectionType::Websocket`，走独立的升级+双向透传链路：发给 origin 的 Upgrade 请求
按头名去重（edge 已透传 `Sec-WebSocket-Key/Version/Upgrade/Connection`，不可重复追加），
读取 origin 的 101 响应头（**不** `read_to_end`），回写 `HttpStatus=101`，随后用
`tokio-util::compat` 把 QUIC 流的 futures 半边桥接到 tokio，与 origin TCP 双向 `copy`。

本地起 `websockets` echo 服务，经公网域名实测：

```
$ python3 tests_ws_client.py ws://test.evec.us.ci/ws-test
sent=hello-0 recv=ECHO: hello-0
sent=hello-1 recv=ECHO: hello-1
sent=hello-2 recv=ECHO: hello-2
WS_E2E_OK

$ python3 tests_ws_stress.py ws://test.evec.us.ci/ws-stress   # 4KB 帧 + 连续 20 帧
WS_STRESS_OK
```

`tests_origin.py`（单端口 aiohttp HTTP+WS origin）+ `tests_ws_client.py` / `tests_ws_stress.py` 为实测脚本，可留作回归测试。

### HTTP/2 fallback 实测（已通过）

H2 是与 QUIC 完全不同的数据面：edge 作为 HTTP/2 客户端，把每条隧道连接作为一次
H2 请求发到本进程（本进程为 H2 server），用 `cf-cloudflared-proxy-connection-upgrade`
头区分 control-stream / websocket / HTTP；HTTP/1 头被序列化进
`cf-cloudflared-request-headers`（响应为 `cf-cloudflared-response-headers`，base64 RawStd
的 `key:value;` 串）。控制流上跑同一套 Cap'n Proto 注册 RPC。

三种协议模式均用真实 token + 公网域名实测通过：

```
# 1) 强制 HTTP2：注册成功，HTTP/WS 数据面正常
$ argo-rs --token '<token>' --protocol http2
隧道注册成功 (HTTP/2) location=lax11 connection_id=28581ec8...
$ curl http://test.evec.us.ci/api/users?id=42
ARGO_RS_E2E_OK path=/api/users?id=42 host=test.evec.us.ci   [HTTP 200]
$ python3 tests_ws_client.py ws://test.evec.us.ci/ws-test
WS_E2E_OK
$ python3 tests_ws_stress.py ws://test.evec.us.ci/ws-stress
WS_STRESS_OK

# 2) auto 默认：QUIC 可用时优先 QUIC，不回退
$ argo-rs --token '<token>'
隧道注册成功 location=lax05 ...        # QUIC，无回退日志

# 3) auto + 阻断 UDP/7844（iptables DROP）：QUIC 握手 5s 超时 × 2 edge 后回退 H2
QUIC 连接失败，回退到 HTTP/2 (TCP 7844)
隧道注册成功 (HTTP/2) location=lax09 ...
$ curl http://test.evec.us.ci/fallback-check
ARGO_RS_E2E_OK path=/fallback-check ...   # 回退后数据面正常
```

三个模式下 Ctrl-C 均能优雅注销，公网随即回到 `530`（Tunnel 离线）。

## 构建

```bash
# 需要 capnproto 编译器（build.rs 用它把 .capnp 编译成 Rust）
#   apt-get install -y capnproto
cargo build --release
```

依赖直连 crates.io。若网络受限，`capnp-rpc` 依赖链已切到 `ring` 加密后端（避开体积巨大的 `aws-lc-sys`）。

## 运行

```bash
./target/release/argo-rs --token '<官方 tunnel token>'
# 或
./target/release/argo-rs --token-file ./token.txt \
    --config ./routes.json --web-addr 127.0.0.1:8080
```

| 参数 | 说明 |
|---|---|
| `--token` / `--token-file` | 官方 tunnel token，二选一 |
| `--protocol <auto\|quic\|http2>` | 边缘传输协议，默认 `auto`（QUIC 优先，失败回退 HTTP/2） |
| `--region` | 指定 edge 区域（默认查全局 SRV） |
| `--edge host:port` | 手动指定 edge，跳过 SRV 发现（调试用） |
| `--web-addr` | 本地配置页监听地址，默认 `127.0.0.1:8080` |
| `--config` | 路由配置 JSON 路径，默认 `routes.json` |

`--protocol auto`（默认）先尝试 QUIC（前 2 个 edge，每个握手 5s 超时）；UDP 不可用时
自动回退到 HTTP/2 over TCP 7844。`quic` / `http2` 强制单一协议。两者共用同一套 token、
注册 RPC 与路由配置。

token 解析后只打印 `tunnel_id` / `account_tag`，secret 全程不落日志。

## 路由配置

浏览器打开 `http://127.0.0.1:8080`，直接编辑 JSON：

```json
{
  "default_port": 8080,
  "routes": [
    { "hostname": "demo.example.com", "path_prefix": "/api", "port": 3000 }
  ]
}
```

`hostname` 可用 `*` 表示默认；`path_prefix` 为空匹配全部。按 hostname + 最长路径前缀匹配，命中后转发到对应本机端口。保存即写盘并即时生效。

## 模块结构

| 文件 | 职责 |
|---|---|
| `src/token.rs` | token base64+JSON 解码（字段 `a`/`s`/`t`/`e`） |
| `src/discovery.rs` | SRV `_v2-origintunneld._tcp.argotunnel.com` + A/AAAA 发现 edge |
| `src/tls.rs` | rustls 客户端配置：系统根 + 内置 Cloudflare Origin CA 根（QUIC 带 ALPN `argotunnel`，H2 不带） |
| `src/quic.rs` | QUIC 连接、控制流、主循环、优雅注销（5s 握手超时） |
| `src/h2.rs` | HTTP/2 传输：TCP+TLS+H2 server、control-stream 注册、HTTP/WS 数据面 |
| `src/h2io.rs` | h2 流 ↔ futures AsyncRead/Write 适配（含流控窗口管理） |
| `src/rpc.rs` | Cap'n Proto RPC：注册/注销（复用官方 schema type ID，QUIC/H2 共用） |
| `src/proxy.rs` | QUIC 数据流：6 字节签名 + `ConnectRequest` 解析 → HTTP 反代 |
| `src/web.rs` / `src/config.rs` | 内嵌配置页与路由热更新 |
| `src/schema/*.capnp` | 从官方源码原样复制的 proto 定义 |

## 已知限制 / 未实现

- 数据面为精简 HTTP/1.1 反代 + WebSocket 升级/双向透传，QUIC 与 HTTP/2 两条传输均已实测；未实现 UDP datagram、裸 TCP 透传
- WebSocket 透传为逐字节 copy，不做帧解析/压缩扩展（permessage-deflate 由 origin 自行协商）
- 未实现远程配置下发、多连接 HA、自动更新、指标上报
- HTTP/2 的 `update-configuration` / edge 反向 RPC 请求未处理（精简版忽略）；配置仅本地网页维护
- H2 数据面按官方头序列化规则处理；`auto` 模式 QUIC 只试前 2 个 edge 以保证回退及时（强制 `--protocol quic` 才遍历全部）
- 注销时 edge 收到请求后立即断开控制流、不回正常 response：QUIC 下 capnp 报 `Disconnected`、H2 下报 `stream closed`，本实现均识别为「注销已接受」
