//! HTTP/2 传输（官方 cloudflared 的 fallback 协议）。
//!
//! 与 QUIC 数据面完全不同：H2 模式下 edge 作为 HTTP/2 客户端，把每条隧道连接
//! 作为一次 HTTP/2 请求发送到本进程（本进程是 H2 server）。请求类型由
//! `cf-cloudflared-proxy-connection-upgrade` 头区分：
//!   - control-stream：控制流，在其请求/响应体上跑 Cap'n Proto 注册 RPC
//!   - websocket：WebSocket 升级
//!   - (空)：普通 HTTP
//! 用户 HTTP/1 头被序列化进 `cf-cloudflared-request-headers`，响应头序列化进
//! `cf-cloudflared-response-headers`（base64 RawStd，`key:value;` 串接）。

use crate::config::{ConfigStore, Service};
use crate::h2io::{H2Reader, H2Writer};
use crate::origin::{self, OriginConn, OriginHead, OriginPool};
use crate::proxy::{parse_http_response, read_response_head};
use crate::rpc::Registration;
use crate::token::TunnelToken;
use crate::tls;
use anyhow::{Context, Result};
use base64::Engine;
use bytes::Bytes;
use futures::AsyncWriteExt as FuturesWriteExt;
use h2::server::{Connection, SendResponse};
use h2::{RecvStream, SendStream};
use http::{Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

const UPGRADE_HEADER: &str = "cf-cloudflared-proxy-connection-upgrade";
const REQUEST_HEADERS: &str = "cf-cloudflared-request-headers";
const RESPONSE_HEADERS: &str = "cf-cloudflared-response-headers";
const RESPONSE_META: &str = "cf-cloudflared-response-meta";
const CONTROL_STREAM: &str = "control-stream";
const WEBSOCKET: &str = "websocket";
const CONFIG_UPDATE: &str = "update-configuration";
const RESPONSE_META_ORIGIN: &str = r#"{"src":"origin","flow_rate_limited":false}"#;

/// 建立到 edge 的 H2 连接，跑控制流注册，然后持续接受 edge 发起的数据流请求。
pub async fn run(
    edge: SocketAddr,
    conn_index: u8,
    token: &TunnelToken,
    secret: &[u8],
    config: Arc<ConfigStore>,
    shutdown: CancellationToken,
    on_registered: &dyn Fn(),
) -> Result<()> {
    // 官方 H2 TLS：SNI h2.cftunnel.com，不设置 ALPN（TLSSettings.NextProtos 为空）。
    let tls_config = tls::build_client_config(vec![])?;
    let connector = TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("h2.cftunnel.com")
        .context("构造 H2 SNI 失败")?;

    info!(%edge, "连接 Cloudflare edge (HTTP/2)");
    let tcp = TcpStream::connect(edge)
        .await
        .with_context(|| format!("H2 TCP 拨号失败: {}", edge))?;
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context("H2 TLS 握手失败")?;
    info!(%edge, "H2 TLS 握手完成");

    // 本进程作为 HTTP/2 server；edge 发来 preface 与 SETTINGS。
    let connection: Connection<TlsStream, Bytes> = h2::server::handshake(tls_stream)
        .await
        .context("HTTP/2 握手失败")?;
    info!(%edge, "HTTP/2 握手完成，等待 edge 请求");

    // h2 要求连接被持续 poll 才能把 SendStream 里缓冲的 DATA 帧刷到 socket。
    // 控制流注册会阻塞等待 RPC 响应，若在主循环里直接 await 会停止 poll 连接，
    // 形成死锁（写出去的消息永远刷不出去）。因此用一个专门的 driver 任务持续
    // accept，把请求通过 channel 交给主循环处理。
    type H2Request = (Request<RecvStream>, SendResponse<Bytes>);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<H2Request>(16);
    let driver = tokio::spawn(async move {
        let mut connection = connection;
        loop {
            match connection.accept().await {
                Some(Ok(pair)) => {
                    if tx.send(pair).await.is_err() {
                        break;
                    }
                }
                Some(Err(e)) => {
                    warn!(%e, "HTTP/2 accept 出错");
                    break;
                }
                None => break,
            }
        }
    });

    let mut registration: Option<Registration> = None;
    let mut edge_closed = false;

    loop {
        tokio::select! {
            incoming = rx.recv() => {
                let (request, respond) = match incoming {
                    Some(pair) => pair,
                    None => {
                        warn!("edge 关闭了 HTTP/2 连接");
                        edge_closed = true;
                        break;
                    }
                };
                debug!(
                    method = %request.method(),
                    uri = %request.uri(),
                    "H2 收到 edge 请求"
                );
                let upgrade = header(&request, UPGRADE_HEADER).unwrap_or_default();
                match upgrade.as_str() {
                    // 控制流必须就地跑完注册：capnp 的 spawn_local 依赖当前
                    // LocalSet 上下文，不能丢进普通 tokio::spawn 任务。
                    CONTROL_STREAM => {
                        match serve_control_stream(request, respond, token, secret, conn_index).await {
                            Ok((reg, info)) => {
                                info!(
                                    location = %info.location,
                                    connection_id = %hex(&info.uuid),
                                    "隧道注册成功 (HTTP/2)"
                                );
                                on_registered();
                                registration = Some(reg);
                            }
                            Err(e) => {
                                warn!(error = format!("{:#}", e), "HTTP/2 控制流注册失败");
                                edge_closed = true;
                                break;
                            }
                        }
                    }
                    CONFIG_UPDATE => {
                        let cfg = config.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_config_update(request, respond, cfg).await {
                                warn!(error = format!("{:#}", e), "处理远程配置更新失败");
                            }
                        });
                    }
                    _ => {
                        let is_ws = upgrade.eq_ignore_ascii_case(WEBSOCKET);
                        let cfg = config.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_data_stream(request, respond, is_ws, cfg).await {
                                warn!(error = format!("{:#}", e), "处理 H2 数据流失败");
                            }
                        });
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("正在注销隧道连接 (HTTP/2)");
                break;
            }
        }
    }

    driver.abort();

    if let Some(registration) = registration {
        if let Err(e) = registration.unregister().await {
            warn!(error = format!("{:#}", e), "注销失败");
        }
        let _ = registration.shutdown().await;
    }
    if edge_closed {
        anyhow::bail!("与 edge 的 HTTP/2 连接已断开");
    }
    Ok(())
}

/// 控制流：edge 用一个 H2 请求打开，请求体是 edge→本进程的 capnp 消息，
/// 响应体是本进程→edge 的 capnp 消息。先回 200 头（不 end stream），再把
/// 请求/响应两半适配成 futures I/O 交给 Cap'n Proto RPC。
async fn serve_control_stream(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    token: &TunnelToken,
    secret: &[u8],
    conn_index: u8,
) -> Result<(Registration, crate::rpc::ConnectionInfo)> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .context("构造控制流响应失败")?;
    let send_stream = respond
        .send_response(response, false)
        .context("发送控制流响应头失败")?;

    let reader = H2Reader::new(request.into_body());
    let writer = H2Writer::new(send_stream);
    Registration::register(reader, writer, token, secret, conn_index).await
}

/// edge 推送远程配置：请求体 `{"version":N,"config":{...}}`，响应 `{"lastAppliedVersion":N,"err":null}`。
async fn serve_config_update(
    request: Request<RecvStream>,
    respond: SendResponse<Bytes>,
    config: Arc<ConfigStore>,
) -> Result<()> {
    let mut reader = H2Reader::new(request.into_body());
    let mut body = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = futures::AsyncReadExt::read(&mut reader, &mut tmp)
            .await
            .context("读取配置更新请求体失败")?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    #[derive(serde::Deserialize)]
    struct UpdateBody {
        version: i32,
        config: serde_json::Value,
    }
    let parsed: UpdateBody = serde_json::from_slice(&body).context("配置更新请求体不是合法 JSON")?;
    let raw = serde_json::to_vec(&parsed.config)?;
    let (applied, err) = config.update(parsed.version, &raw);
    // 与官方 pogs 的 JSON 形态一致：err 为 nil 时 null，否则是 Go error 序列化出的 {}。
    let resp = serde_json::json!({
        "lastAppliedVersion": applied,
        "err": err.map(|_| serde_json::json!({})),
    });
    let resp_body = serde_json::to_vec(&resp)?;
    let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    let send_stream = write_h2_response(respond, 200, &headers, &resp_body, false).await?;
    drop(send_stream);
    Ok(())
}

/// 单条 H2 数据流：解析伪头与序列化请求头 → 转发到本机 origin → 把响应头
/// 序列化回 H2 头，body 作为 DATA 帧写回。
async fn serve_data_stream(
    request: Request<RecvStream>,
    respond: SendResponse<Bytes>,
    is_ws: bool,
    config: Arc<ConfigStore>,
) -> Result<()> {
    let method = request.method().as_str().to_string();
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // 请求头：优先反序列化 cf-cloudflared-request-headers，再叠加其余原生 H2 头。
    let mut headers = Vec::new();
    if let Some(serialized) = header(&request, REQUEST_HEADERS) {
        headers = deserialize_headers(&serialized)?;
    }
    for (name, value) in request.headers() {
        let name = name.as_str();
        if name.starts_with(':') || name == REQUEST_HEADERS || name == UPGRADE_HEADER {
            continue;
        }
        let value = match value.to_str() {
            Ok(v) => v.to_string(),
            Err(_) => continue,
        };
        if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)) {
            continue;
        }
        headers.push((name.to_string(), value));
    }

    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .or_else(|| request.uri().authority().map(|a| a.to_string()))
        .or_else(|| header(&request, "host"))
        .unwrap_or_default();

    let target = config.resolve(&host, &path);
    let recv = request.into_body();
    let (origin_host, port, host) = match target.service {
        Service::Http { host: origin_host, port } => {
            (origin_host, port, target.host_header.unwrap_or(host))
        }
        Service::Status(code) => {
            debug!(%host, %path, code, "命中 http_status 规则");
            let send_stream = write_h2_response(respond, code, &[], b"", false).await?;
            drop(send_stream);
            return Ok(());
        }
        Service::Unsupported(service) => {
            warn!(%service, %host, "命中不受支持的 ingress service，返回 502");
            let send_stream = write_h2_response(respond, 502, &[], b"", false).await?;
            drop(send_stream);
            return Ok(());
        }
    };
    debug!(%host, %path, %origin_host, port, is_ws, "H2 转发到 origin");

    if is_ws {
        serve_websocket(&method, &path, &host, &headers, origin_host, port, recv, respond).await
    } else {
        serve_http(&method, &path, &host, &headers, origin_host, port, recv, respond).await
    }
}

/// 取一条可用 origin 连接并发请求、读响应头：优先复用池内 keep-alive 连接，
/// 失效则重建一次；新建连接失败意味着 origin 不可达，直接上抛（调用方回 502）。
async fn request_origin(
    origin_host: &str,
    port: u16,
    head: &[u8],
    body: &[u8],
) -> Result<(OriginConn, OriginHead)> {
    if let Some(mut conn) = OriginPool::global().checkout(origin_host, port) {
        match send_origin_request(&mut conn, head, body).await {
            Ok(head) => return Ok((conn, head)),
            Err(e) => debug!(error = format!("{e:#}"), "复用的 origin 连接已失效，重建连接"),
        }
    }
    let mut conn = OriginConn::connect(origin_host, port).await?;
    let head = send_origin_request(&mut conn, head, body).await?;
    Ok((conn, head))
}

async fn send_origin_request(conn: &mut OriginConn, head: &[u8], body: &[u8]) -> Result<OriginHead> {
    conn.writer.write_all(head).await.context("发送请求到 origin 失败")?;
    if !body.is_empty() {
        conn.writer.write_all(body).await.context("发送请求体到 origin 失败")?;
    }
    origin::read_head(conn).await
}

async fn serve_http(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    origin_host: String,
    port: u16,
    recv: RecvStream,
    respond: SendResponse<Bytes>,
) -> Result<()> {
    // 读请求体（H2 用流结束标记界定长度）。
    let mut body = Vec::new();
    let mut reader = H2Reader::new(recv);
    let mut tmp = [0u8; 8192];
    loop {
        let n = futures::AsyncReadExt::read(&mut reader, &mut tmp)
            .await
            .context("读取 H2 请求体失败")?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    let mut req = build_origin_request(method, path, host, headers, false);
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    // 不发 Connection: close，HTTP/1.1 默认 keep-alive，连接可回池复用。
    req.push_str("\r\n");

    // 连接/发送/读响应头失败统一回 502：访客拿到明确的网关错误而不是断流。
    let (mut conn, head) = match request_origin(&origin_host, port, req.as_bytes(), &body).await {
        Ok(ok) => ok,
        Err(e) => {
            warn!(error = format!("{e:#}"), "origin 请求失败，返回 502");
            let send_stream =
                write_h2_response(respond, 502, &[], b"origin 请求失败", false).await?;
            drop(send_stream);
            return Ok(());
        }
    };

    let framing = origin::classify(&head, method);
    let content_length = match framing {
        origin::Framing::Length(n) => Some(n.to_string()),
        _ => None,
    };
    let fwd = origin::forward_headers(&head, framing);
    let send_stream =
        write_h2_streaming_head(respond, head.status, &fwd, content_length.as_deref()).await?;
    let mut h2w = H2Writer::new(send_stream);

    let streamed = match framing {
        origin::Framing::None => Ok(()),
        origin::Framing::Length(n) => origin::copy_exact(&mut conn.reader, &mut h2w, n).await,
        origin::Framing::Chunked => origin::copy_chunked(&mut conn.reader, &mut h2w).await,
        origin::Framing::Eof => origin::copy_until_eof(&mut conn.reader, &mut h2w).await,
    };
    match streamed {
        Ok(()) => {
            h2w.finish().context("结束 H2 响应流失败")?;
            if origin::reusable(&head, framing) {
                OriginPool::global().checkin(&origin_host, port, conn);
            }
            Ok(())
        }
        Err(e) => {
            // 响应头已发出无法再改 502；不 finish（send_stream 随 drop 复位流），
            // 错误上抛由调用方记录。
            Err(e)
        }
    }
}

async fn serve_websocket(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    origin_host: String,
    port: u16,
    recv: RecvStream,
    respond: SendResponse<Bytes>,
) -> Result<()> {
    // websocket 是长连接 hijack，不走连接池（与官方一致，每次单独拨号）。
    let upstream = match TcpStream::connect((origin_host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!(origin = %origin_host, port, error = %e, "连接 origin 失败，返回 502");
            let send_stream = write_h2_response(respond, 502, &[], b"origin 请求失败", false).await?;
            drop(send_stream);
            return Ok(());
        }
    };
    let mut upstream = upstream;
    let req = build_origin_request(method, path, host, headers, true);
    upstream.write_all(req.as_bytes()).await?;

    // 只读响应头到 \r\n\r\n，绝不 read_to_end（101 后连接保持打开）。
    let mut buf = tokio::io::BufReader::new(upstream);
    let head = read_response_head(&mut buf).await?;
    let (status, resp_headers, _) = parse_http_response(&head)?;
    if status != 101 {
        warn!(status, "origin 未返回 101，WebSocket 升级失败");
        let send_stream =
            write_h2_response(respond, status, &resp_headers, b"", false).await?;
        drop(send_stream);
        return Ok(());
    }

    // HTTP/2 不支持 101：官方把 101 改写成 200，真正的升级头放进序列化头里，
    // 升级完成后 stream 变成裸字节通道（hijack），与 QUIC 模式一致。
    // hijack=true 时只发头，不写 body 也不结束流。
    let send_stream = write_h2_response(respond, 101, &resp_headers, b"", true).await?;

    // 握手完成，两侧裸字节双向透传。h2 流用适配器，origin 保留 tokio I/O。
    let edge_read = H2Reader::new(recv).compat();
    let edge_write = H2Writer::new(send_stream).compat_write();
    tokio::pin!(edge_read);
    tokio::pin!(edge_write);
    let (mut up_read, mut up_write) = tokio::io::split(buf);

    let to_origin = tokio::io::copy(&mut edge_read, &mut up_write);
    let to_edge = tokio::io::copy(&mut up_read, &mut edge_write);
    tokio::select! {
        r = to_origin => { r.context("客户端→origin 透传失败")?; },
        r = to_edge => { r.context("origin→客户端 透传失败")?; },
    }
    Ok(())
}

/// 把 edge 的请求头拼成 HTTP/1.1 请求发给 origin。
/// websocket 模式保留升级头（按头名去重、补齐缺失头），http 模式过滤 hop-by-hop。
fn build_origin_request(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    ws: bool,
) -> String {
    let mut out = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);
    let mut present: Vec<String> = Vec::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        let skip = lower == "host"
            || lower == "content-length"
            || lower == ":authority"
            || lower == ":method"
            || lower == ":path"
            || (!ws
                && (lower == "connection"
                    || lower == "upgrade"
                    || lower == "transfer-encoding"));
        if skip {
            continue;
        }
        if present.iter().any(|p| p.eq_ignore_ascii_case(&lower)) {
            continue;
        }
        present.push(lower.clone());
        out.push_str(&format!("{}: {}\r\n", name, value));
    }
    if ws {
        let has = |n: &str| present.iter().any(|p| p.eq_ignore_ascii_case(n));
        if !has("connection") {
            out.push_str("Connection: Upgrade\r\n");
        }
        if !has("upgrade") {
            out.push_str("Upgrade: websocket\r\n");
        }
        if !has("sec-websocket-version") {
            out.push_str("Sec-WebSocket-Version: 13\r\n");
        }
        out.push_str("\r\n");
    }
    out
}

/// 写 HTTP/2 响应头：status（101→200）、序列化用户头、response-meta。
/// 返回 SendStream<Bytes> 供调用方决定写 body 或继续 hijack 透传。
async fn write_h2_response(
    mut respond: SendResponse<Bytes>,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    hijack: bool,
) -> Result<SendStream<Bytes>> {
    // 非 hijack 时沿用 origin 的 content-length（若有）；hijack（websocket 101）
    // 不带 body，不声明长度。
    let content_length = if hijack {
        None
    } else {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.clone())
    };
    let response = build_h2_response(status, headers, content_length.as_deref())?;
    let end = body.is_empty() && !hijack;
    let mut send_stream = respond
        .send_response(response, end)
        .context("发送 H2 响应头失败")?;

    if !body.is_empty() {
        let mut writer = H2Writer::new(send_stream);
        FuturesWriteExt::write_all(&mut writer, body)
            .await
            .context("发送 H2 响应体失败")?;
        if !hijack {
            writer.finish().context("结束 H2 响应流失败")?;
        }
        send_stream = writer.into_inner();
    }
    Ok(send_stream)
}

/// 流式响应专用：只发响应头（不结束流），body 由调用方按分帧逐块写入后 finish。
/// content-length 由分帧判定结果显式给出（chunked/EOF 分帧为 None）。
async fn write_h2_streaming_head(
    respond: SendResponse<Bytes>,
    status: u16,
    headers: &[(String, String)],
    content_length: Option<&str>,
) -> Result<SendStream<Bytes>> {
    let response = build_h2_response(status, headers, content_length)?;
    respond
        .send_response(response, false)
        .context("发送 H2 响应头失败")
}

/// 构造 H2 响应：过滤内部头与伪头，剥离 content-length（由调用方显式传入）。
fn build_h2_response(
    status: u16,
    headers: &[(String, String)],
    content_length: Option<&str>,
) -> Result<Response<()>> {
    let mut user_headers: Vec<(String, String)> = Vec::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "content-length" {
            continue;
        }
        let is_control = lower.starts_with(':')
            || lower.starts_with("cf-int-")
            || lower.starts_with("cf-cloudflared-")
            || lower.starts_with("cf-proxy-");
        let is_ws_client = matches!(
            lower.as_str(),
            "sec-websocket-accept" | "connection" | "upgrade"
        );
        if is_control && !is_ws_client {
            continue;
        }
        user_headers.push((name.clone(), value.clone()));
    }

    let h2_status = if status == 101 { 200 } else { status };
    let mut builder = Response::builder().status(StatusCode::from_u16(h2_status)?);
    if let Some(cl) = content_length {
        builder = builder.header("content-length", cl);
    }
    builder = builder
        .header(RESPONSE_HEADERS, serialize_headers(&user_headers))
        .header(RESPONSE_META, RESPONSE_META_ORIGIN);
    builder.body(()).context("构造 H2 响应失败")
}

fn serialize_headers(headers: &[(String, String)]) -> String {
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let mut out = String::new();
    for (i, (name, value)) in headers.iter().enumerate() {
        if i > 0 {
            out.push(';');
        }
        out.push_str(&engine.encode(name.as_bytes()));
        out.push(':');
        out.push_str(&engine.encode(value.as_bytes()));
    }
    out
}

fn deserialize_headers(serialized: &str) -> Result<Vec<(String, String)>> {
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let mut out = Vec::new();
    for pair in serialized.split(';') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once(':').context("非法的序列化请求头")?;
        let name = String::from_utf8(engine.decode(name).context("请求头名 base64 解码失败")?)?;
        let value =
            String::from_utf8(engine.decode(value).context("请求头值 base64 解码失败")?)?;
        out.push((name, value));
    }
    Ok(out)
}

fn header<R>(request: &Request<R>, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
