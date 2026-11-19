use crate::config::{ConfigStore, Service};
use crate::quic_metadata_protocol_capnp as quic_schema;
use crate::stream::QuinnDuplex;
use anyhow::{bail, Context, Result};
use capnp::message::ReaderOptions;
use futures::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
// TcpStream / compat 流实现的是 tokio 的 I/O trait，用 `as _` 引入避免与 futures 同名 trait 冲突。
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// 官方 tunnelrpc/quic/protocol.go 里的流签名与版本。
pub(crate) const DATA_SIGNATURE: [u8; 6] = [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E];
/// edge 反向调用 cloudflared 的 RPC 流（远程配置下发），由 quic.rs 按签名分派给 rpc.rs。
pub(crate) const RPC_SIGNATURE: [u8; 6] = [0x52, 0xBB, 0x82, 0x5C, 0xDB, 0x65];
const PROTOCOL_VERSION: &[u8] = b"01";

/// websocket 升级需要传给 origin 的 RFC6455 GUID（用于校验响应，实际 Accept 由 origin 计算）。
/// 这里仅保留常量以备日志/调试，签名校验交给本地 origin 服务自身。
const _WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

type EdgeReader = BufReader<quinn::RecvStream>;
type EdgeWriter = BufWriter<quinn::SendStream>;

struct RequestInfo {
    method: String,
    host: String,
    path: String,
    origin_host: String,
    port: u16,
    metadata: HashMap<String, String>,
}

fn split_url(dest: &str) -> (String, String) {
    let rest = match dest.find("://") {
        Some(i) => &dest[i + 3..],
        None => dest,
    };
    match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    }
}

/// 调用前 quic.rs 已读掉 6 字节数据流签名，这里从 2 字节版本号开始。
pub async fn serve_data_stream(stream: QuinnDuplex, config: Arc<ConfigStore>) -> Result<()> {
    let mut reader = BufReader::new(stream.recv);
    let mut writer = BufWriter::new(stream.send);

    let is_ws = read_and_dispatch(&mut reader, &mut writer, &config).await;
    if let Err(e) = is_ws {
        // 区分：连接类错误仍需记录；这里统一由调用方记录，保持返回语义。
        return Err(e);
    }
    Ok(())
}

/// 读取一条数据流，完成签名/ConnectRequest 解析后按 HTTP 或 WebSocket 分派。
/// 返回 bool 表示是否为 websocket（供将来统计），错误向外传播。
async fn read_and_dispatch(
    reader: &mut EdgeReader,
    writer: &mut EdgeWriter,
    config: &ConfigStore,
) -> Result<bool> {
    let mut version = [0u8; 2];
    reader.read_exact(&mut version).await.context("读取流版本失败")?;
    if &version[..] != PROTOCOL_VERSION {
        bail!("不支持的数据流协议版本");
    }

    let message = capnp_futures::serialize::read_message(&mut *reader, ReaderOptions::new())
        .await
        .context("读取 ConnectRequest 失败")?;
    let request = message.get_root::<quic_schema::connect_request::Reader>()?;
    let dest = request.get_dest()?.to_string()?;
    let mut metadata = HashMap::new();
    for entry in request.get_metadata()?.iter() {
        metadata.insert(entry.get_key()?.to_string()?, entry.get_val()?.to_string()?);
    }
    let connection_type = request.get_type()?;

    if connection_type != quic_schema::ConnectionType::Http
        && connection_type != quic_schema::ConnectionType::Websocket
    {
        warn!(?connection_type, "暂不支持非 HTTP 请求，返回 502");
        write_error(writer, 502, "unsupported connection type").await?;
        return Ok(false);
    }
    // drop message 借用后进入下游；metadata 已拷贝为拥有类型。
    drop(message);

    let method = metadata
        .get("HttpMethod")
        .cloned()
        .unwrap_or_else(|| "GET".to_string());
    let (url_host, path_and_query) = split_url(&dest);
    let host = metadata
        .get("HttpHost")
        .cloned()
        .unwrap_or_else(|| url_host.clone());
    let target = config.resolve(&host, &path_and_query);
    let (origin_host, port, host) = match target.service {
        Service::Http { host: origin_host, port } => {
            (origin_host, port, target.host_header.unwrap_or(host))
        }
        Service::Status(code) => {
            debug!(%host, %path_and_query, code, "命中 http_status 规则");
            write_connect_response(writer, code, &[]).await?;
            writer.flush().await?;
            return Ok(false);
        }
        Service::Unsupported(service) => {
            warn!(%service, %host, "命中不受支持的 ingress service，返回 502");
            write_error(writer, 502, "unsupported ingress service").await?;
            return Ok(false);
        }
    };
    debug!(%host, %path_and_query, %origin_host, port, ?connection_type, "转发到 origin");

    let info = RequestInfo {
        method,
        host,
        path: path_and_query,
        origin_host,
        port,
        metadata,
    };

    match connection_type {
        quic_schema::ConnectionType::Websocket => {
            serve_websocket(reader, writer, info).await?;
            Ok(true)
        }
        _ => {
            serve_http(reader, writer, info).await?;
            Ok(false)
        }
    }
}

/// 普通 HTTP：读请求体 → 发 origin → read_to_end 响应 → 一次性写回。
async fn serve_http(reader: &mut EdgeReader, writer: &mut EdgeWriter, info: RequestInfo) -> Result<()> {
    let content_length = info
        .metadata
        .get("HttpHeader:Content-Length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await.context("读取请求体失败")?;
    }

    let mut upstream = TcpStream::connect((info.origin_host.as_str(), info.port))
        .await
        .with_context(|| format!("连接 origin {}:{} 失败", info.origin_host, info.port))?;

    let mut headers = String::new();
    headers.push_str(&format!("{} {} HTTP/1.1\r\n", info.method, info.path));
    headers.push_str(&format!("Host: {}\r\n", info.host));
    let mut present = Vec::new();
    append_request_headers(&mut headers, &info.metadata, true, &mut present);
    headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
    headers.push_str("Connection: close\r\n\r\n");
    upstream.write_all(headers.as_bytes()).await?;
    upstream.write_all(&body).await?;

    let mut response = Vec::new();
    upstream.read_to_end(&mut response).await.context("读取本地服务响应失败")?;
    let (status, response_headers, resp_body) = parse_http_response(&response)?;

    write_connect_response(writer, status, &response_headers).await?;
    writer.write_all(resp_body).await?;
    writer.flush().await?;
    Ok(())
}

/// WebSocket：发 Upgrade 请求 → 读 origin 的 101 响应头 → 回写 ConnectResponse → 双向裸字节透传。
async fn serve_websocket(
    reader: &mut EdgeReader,
    writer: &mut EdgeWriter,
    info: RequestInfo,
) -> Result<()> {
    let mut upstream = TcpStream::connect((info.origin_host.as_str(), info.port))
        .await
        .with_context(|| format!("连接 origin {}:{} 失败", info.origin_host, info.port))?;

    // 官方 proxyHTTPRequest：websocket 请求无 body，并补齐缺失的升级头。
    // edge 通常已透传 Sec-WebSocket-Key/Version/Upgrade/Connection，重复追加会导致
    // origin 拒绝（如 Sec-WebSocket-Version multiple values），因此按头名去重。
    let mut headers = String::new();
    headers.push_str(&format!("{} {} HTTP/1.1\r\n", info.method, info.path));
    headers.push_str(&format!("Host: {}\r\n", info.host));
    let mut present: Vec<String> = Vec::new();
    append_request_headers(&mut headers, &info.metadata, false, &mut present);
    let has = |name: &str| present.iter().any(|p| p.eq_ignore_ascii_case(name));
    if !has("connection") {
        headers.push_str("Connection: Upgrade\r\n");
    }
    if !has("upgrade") {
        headers.push_str("Upgrade: websocket\r\n");
    }
    if !has("sec-websocket-version") {
        headers.push_str("Sec-WebSocket-Version: 13\r\n");
    }
    headers.push_str("\r\n");
    debug!(%info.host, "发送 WebSocket Upgrade 请求到 origin");
    upstream.write_all(headers.as_bytes()).await?;

    // 只读响应头到 \r\n\r\n，绝不 read_to_end（101 后连接保持打开）。
    let mut upstream_buf = tokio::io::BufReader::new(upstream);
    let head = read_response_head(&mut upstream_buf).await?;
    let (status, response_headers, _) = parse_http_response(&head)?;
    if status != 101 {
        warn!(status, "origin 未返回 101，WebSocket 升级失败");
        write_connect_response(writer, status, &response_headers).await?;
        writer.flush().await?;
        return Ok(());
    }

    debug!("WebSocket 升级成功，进入双向透传");
    write_connect_response(writer, status, &response_headers).await?;
    writer.flush().await?;

    // 握手完成，把两侧的 futures 流桥接到 tokio 后双向 copy。
    // compat 保留 BufReader 中已预读但未消费的字节，避免丢失首个 WS 帧。
    let mut edge_read = reader.compat();
    let mut edge_write = writer.compat_write();
    let (mut up_read, mut up_write) = tokio::io::split(upstream_buf);

    let to_origin = tokio::io::copy(&mut edge_read, &mut up_write);
    let to_edge = tokio::io::copy(&mut up_read, &mut edge_write);
    tokio::select! {
        r = to_origin => { r.context("客户端→origin 透传失败")?; },
        r = to_edge => { r.context("origin→客户端 透传失败")?; },
    }
    Ok(())
}

/// 把 metadata 里的 HttpHeader:* 追加到请求头。
/// http_mode=true 时过滤掉 hop-by-hop 头；websocket 模式保留原始头（含 Sec-WebSocket-Key）。
fn append_request_headers(
    out: &mut String,
    metadata: &HashMap<String, String>,
    http_mode: bool,
    present: &mut Vec<String>,
) {
    for (key, value) in metadata {
        if let Some(name) = key.strip_prefix("HttpHeader:") {
            let lower = name.to_ascii_lowercase();
            let skip = lower == "host"
                || lower == "content-length"
                || (http_mode
                    && (lower == "connection"
                        || lower == "upgrade"
                        || lower == "sec-websocket-key"
                        || lower == "sec-websocket-version"));
            if !skip {
                present.push(name.to_string());
                out.push_str(&format!("{}: {}\r\n", name, value));
            }
        }
    }
}

/// 从字节流中解析 HTTP 响应：状态行 / 响应头列表 / body。
pub(crate) fn parse_http_response(response: &[u8]) -> Result<(u16, Vec<(String, String)>, &[u8])> {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("本地服务返回了非法 HTTP 响应（缺少头部结束符）")?;
    let head = &response[..split + 4];
    let body = &response[split + 4..];

    let status_line = String::from_utf8_lossy(head)
        .lines()
        .next()
        .unwrap_or("HTTP/1.1 502 Bad Gateway")
        .to_string();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);

    let mut headers = Vec::new();
    for line in String::from_utf8_lossy(head).lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            // HTTP 模式跳过 hop-by-hop；websocket 模式下这些头正是握手所需，全部保留。
            if status != 101 {
                let lower = name.trim().to_ascii_lowercase();
                if lower == "transfer-encoding" || lower == "connection" {
                    continue;
                }
            }
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok((status, headers, body))
}

/// 逐行读取响应头直到空行（\r\n），返回包含结束符的头部字节。
pub(crate) async fn read_response_head<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut head = Vec::new();
    loop {
        let n = reader.read_until(b'\n', &mut head).await.context("读取 origin 响应头失败")?;
        if n == 0 {
            bail!("origin 在响应头完成前关闭了连接");
        }
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
        if head.len() > 64 * 1024 {
            bail!("origin 响应头过大");
        }
    }
    Ok(head)
}

/// 写 ConnectResponse（6字节签名 + 版本 + capnp metadata）。
async fn write_connect_response(
    writer: &mut EdgeWriter,
    status: u16,
    headers: &[(String, String)],
) -> Result<()> {
    writer.write_all(&DATA_SIGNATURE).await?;
    writer.write_all(PROTOCOL_VERSION).await?;
    let mut message = capnp::message::Builder::new_default();
    {
        let mut root = message.init_root::<quic_schema::connect_response::Builder>();
        root.set_error("");
        let mut list = root.init_metadata((headers.len() + 1) as u32);
        let status_text = status.to_string();
        let mut status_meta = list.reborrow().get(0);
        status_meta.set_key("HttpStatus");
        status_meta.set_val(status_text.as_str());
        for (i, (name, value)) in headers.iter().enumerate() {
            let mut meta = list.reborrow().get(i as u32 + 1);
            meta.set_key(&format!("HttpHeader:{}", name));
            meta.set_val(value);
        }
    }
    capnp_futures::serialize::write_message(writer, message).await?;
    Ok(())
}

async fn write_error<W>(writer: &mut W, status: u16, message: &str) -> Result<()>
where
    W: futures::AsyncWrite + Unpin,
{
    writer.write_all(&DATA_SIGNATURE).await?;
    writer.write_all(PROTOCOL_VERSION).await?;
    let mut capnp_msg = capnp::message::Builder::new_default();
    {
        let mut root = capnp_msg.init_root::<quic_schema::connect_response::Builder>();
        root.set_error(message);
        let mut list = root.init_metadata(1);
        let mut meta = list.reborrow().get(0);
        let status_text = status.to_string();
        meta.set_key("HttpStatus");
        meta.set_val(status_text.as_str());
    }
    capnp_futures::serialize::write_message(&mut *writer, capnp_msg).await?;
    writer.flush().await?;
    Ok(())
}
