//! origin 连接池与响应流式转发。
//!
//! 对齐官方 cloudflared ingress/origin_service.go 的 newHTTPTransport 语义：
//! HTTP/1.1 keep-alive 连接池（MaxIdleConns=100，IdleConnTimeout=90s），响应体
//! 不整段缓冲，按 Content-Length / chunked / EOF 三种分帧逐块回传 edge。

use crate::config::OriginTls;
use crate::proxy::read_response_head;
use anyhow::{bail, Context, Result};
use futures::AsyncWriteExt as FuturesWriteExt;
use std::collections::HashMap;
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as TokioReadExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// 对齐官方默认：keepAliveConnections=100。
const MAX_IDLE_PER_HOST: usize = 100;
/// 对齐官方默认：keepAliveTimeout=90s。
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// 流式回传 edge 的块大小。
const STREAM_CHUNK: usize = 16 * 1024;

/// 一条到 origin 的 HTTP/1.1 连接：writer 直写 socket，reader 带缓冲读响应。
/// 读写两半指向同一 socket（明文 TCP 用 into_split，TLS 用 tokio::io::split），
/// 响应体读完后可整体回池复用。boxed trait 统一明文与 rustls 两条路径。
pub struct OriginConn {
    pub writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    pub reader: BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
}

type BoxedRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
type BoxedWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

impl OriginConn {
    pub async fn connect(host: &str, port: u16, tls: Option<&OriginTls>) -> Result<Self> {
        let stream = TcpStream::connect((host, port))
            .await
            .with_context(|| format!("连接 origin {host}:{port} 失败"))?;
        match tls {
            None => {
                let (read_half, write_half) = stream.into_split();
                Ok(Self {
                    writer: Box::new(write_half) as BoxedWrite,
                    reader: BufReader::new(Box::new(read_half) as BoxedRead),
                })
            }
            Some(tls) => {
                let config = tls_config(tls)?;
                let connector = TlsConnector::from(config);
                let name = tls.server_name.as_deref().unwrap_or(host);
                let server_name = if let Ok(ip) = name.parse::<IpAddr>() {
                    rustls::pki_types::ServerName::from(ip)
                } else {
                    rustls::pki_types::ServerName::try_from(name.to_string())
                        .with_context(|| format!("非法的 origin ServerName: {name}"))?
                };
                let tls_stream = tokio::time::timeout(Duration::from_secs(10), async {
                    connector.connect(server_name.to_owned(), stream).await
                })
                .await
                .context("origin TLS 握手超时")?
                .context("origin TLS 握手失败")?;
                let (read_half, write_half) = tokio::io::split(tls_stream);
                Ok(Self {
                    writer: Box::new(write_half) as BoxedWrite,
                    reader: BufReader::new(Box::new(read_half) as BoxedRead),
                })
            }
        }
    }
}

/// TLS ClientConfig 按参数指纹缓存，避免每条连接重建证书池。
fn tls_config(tls: &OriginTls) -> Result<std::sync::Arc<rustls::ClientConfig>> {
    static CACHE: OnceLock<Mutex<HashMap<String, std::sync::Arc<rustls::ClientConfig>>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let fingerprint = tls.fingerprint();
    if let Some(config) = cache.lock().unwrap().get(&fingerprint) {
        return Ok(config.clone());
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ca) = &tls.ca_pool {
        let pem = if ca.trim_start().starts_with("-----BEGIN") {
            ca.as_bytes().to_vec()
        } else {
            std::fs::read(ca).with_context(|| format!("读取 origin CA 池失败: {ca}"))?
        };
        let certs = rustls_pemfile::certs(&mut Cursor::new(pem))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("解析 origin CA 池 PEM 失败")?;
        bail_if_empty(&certs, &fingerprint)?;
        for cert in certs {
            roots.add(cert).context("写入 origin CA 池失败")?;
        }
    }

    let builder = rustls::ClientConfig::builder();
    let builder = if tls.no_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerifier))
    } else {
        builder.with_root_certificates(roots)
    };
    // 源站只支持 HTTP/1.1 手写请求；与官方 ForceAttemptHTTP2 的区别在此明确收敛。
    let mut config = builder.with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = std::sync::Arc::new(config);
    cache.lock().unwrap().insert(fingerprint, config.clone());
    debug!(no_verify = tls.no_verify, "已构建 origin TLS 配置");
    Ok(config)
}

fn bail_if_empty(certs: &[rustls::pki_types::CertificateDer<'_>], fp: &str) -> Result<()> {
    if certs.is_empty() {
        bail!("origin CA 池中没有证书: {fp}");
    }
    Ok(())
}

/// 对应官方 noTLSVerify：仅跳过证书链校验，签名仍由 ring 验证。
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 连接池 key：含 TLS 指纹，明文/HTTPS 与不同 TLS 参数互不复用。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub host: String,
    pub port: u16,
    pub tls: String,
}

impl PoolKey {
    pub fn new(host: &str, port: u16, tls: Option<&OriginTls>) -> Self {
        Self {
            host: host.to_string(),
            port,
            tls: tls.map(OriginTls::fingerprint).unwrap_or_default(),
        }
    }
}

struct PooledConn {
    conn: OriginConn,
    idle_since: Instant,
}

/// HTTP/1.1 keep-alive 连接池，按 PoolKey 分桶。
pub struct OriginPool {
    conns: Mutex<HashMap<PoolKey, Vec<PooledConn>>>,
}

impl OriginPool {
    pub fn global() -> &'static Self {
        static POOL: OnceLock<OriginPool> = OnceLock::new();
        POOL.get_or_init(|| OriginPool {
            conns: Mutex::new(HashMap::new()),
        })
    }

    /// 取一条空闲连接；超期连接顺手丢弃。
    pub fn checkout(&self, key: &PoolKey) -> Option<OriginConn> {
        let mut conns = self.conns.lock().unwrap();
        let bucket = conns.get_mut(key)?;
        while let Some(pooled) = bucket.pop() {
            if pooled.idle_since.elapsed() < IDLE_TIMEOUT {
                return Some(pooled.conn);
            }
            // 超期连接直接丢弃，随 drop 关闭 socket。
        }
        None
    }

    /// 归还一条仍可复用的连接；超出每主机空闲上限时直接丢弃。
    pub fn checkin(&self, key: &PoolKey, conn: OriginConn) {
        let mut conns = self.conns.lock().unwrap();
        let bucket = conns.entry(key.clone()).or_default();
        if bucket.len() >= MAX_IDLE_PER_HOST {
            return;
        }
        bucket.push(PooledConn {
            conn,
            idle_since: Instant::now(),
        });
    }
}

/// origin 响应头：状态行 + 原始头列表（未过滤 hop-by-hop）。
pub struct OriginHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

/// 读取并解析 origin 响应头（只读到头部结束符，不读 body）。
pub async fn read_head(conn: &mut OriginConn) -> Result<OriginHead> {
    let head = read_response_head(&mut conn.reader).await?;
    parse_head(&head)
}

fn parse_head(head: &[u8]) -> Result<OriginHead> {
    let text = String::from_utf8_lossy(head);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .context("origin 返回了非法状态行")?;
    let headers = text
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();
    Ok(OriginHead { status, headers })
}

/// origin 响应体的分帧方式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// 无响应体（1xx / 204 / 304 / HEAD）。
    None,
    /// Content-Length 定长。
    Length(u64),
    /// Transfer-Encoding: chunked，逐块解码转发。
    Chunked,
    /// 无分帧声明，读到 origin 关闭连接为止。
    Eof,
}

/// 根据状态码与响应头判定响应体分帧。
/// 204/304/HEAD/1xx 必须判为 None，否则 keep-alive 下按 EOF 读会挂死。
pub fn classify(head: &OriginHead, method: &str) -> Framing {
    if head.status < 200
        || head.status == 204
        || head.status == 304
        || method.eq_ignore_ascii_case("HEAD")
    {
        return Framing::None;
    }
    let mut te_chunked = false;
    let mut content_length = None;
    for (name, value) in &head.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            te_chunked = true;
        } else if lower == "content-length" {
            content_length = value.trim().parse().ok();
        }
    }
    if te_chunked {
        Framing::Chunked
    } else if let Some(n) = content_length {
        Framing::Length(n)
    } else {
        Framing::Eof
    }
}

/// 过滤 hop-by-hop 头后得到可回传 edge 的头列表。
/// content-length 仅在定长分帧或无 body（HEAD/204 等声明值）时保留，
/// chunked/EOF 分帧的响应不能带 content-length。
pub fn forward_headers(head: &OriginHead, framing: Framing) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in &head.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        ) {
            continue;
        }
        if lower == "content-length" {
            if matches!(framing, Framing::Length(_) | Framing::None) {
                out.push((name.clone(), value.clone()));
            }
            continue;
        }
        out.push((name.clone(), value.clone()));
    }
    out
}

/// 响应体按分帧读完后，该连接是否可回池复用。
pub fn reusable(head: &OriginHead, framing: Framing) -> bool {
    if framing == Framing::Eof {
        // EOF 分帧读完即连接关闭，无从复用。
        return false;
    }
    !head.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection") && value.to_ascii_lowercase().contains("close")
    })
}

/// 定长分帧：精确回传 remaining 字节，不足即报错（连接不可复用）。
pub async fn copy_exact<R, W>(reader: &mut R, writer: &mut W, mut remaining: u64) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: futures::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; STREAM_CHUNK];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = reader
            .read(&mut buf[..want])
            .await
            .context("读取 origin 响应体失败")?;
        if n == 0 {
            bail!("origin 响应体在 Content-Length 结束前被截断");
        }
        writer
            .write_all(&buf[..n])
            .await
            .context("回传 edge 响应体失败")?;
        writer.flush().await.context("回传 edge 响应体失败")?;
        remaining -= n as u64;
    }
    Ok(())
}

/// EOF 分帧：读到 origin 关闭连接为止。
pub async fn copy_until_eof<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: futures::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; STREAM_CHUNK];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .context("读取 origin 响应体失败")?;
        if n == 0 {
            return Ok(());
        }
        writer
            .write_all(&buf[..n])
            .await
            .context("回传 edge 响应体失败")?;
        writer.flush().await.context("回传 edge 响应体失败")?;
    }
}

/// chunked 分帧：边解码分帧边回传，edge 收到的是纯数据。
pub async fn copy_chunked<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: futures::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; STREAM_CHUNK];
    loop {
        let mut line = Vec::new();
        let n = reader
            .read_until(b'\n', &mut line)
            .await
            .context("读取 chunk 大小行失败")?;
        if n == 0 {
            bail!("origin 在 chunked 响应结束前关闭了连接");
        }
        let size = parse_chunk_size(&line)?;
        if size == 0 {
            // 终止块：消费 trailer 直到空行。
            loop {
                let mut trailer = Vec::new();
                let tn = reader.read_until(b'\n', &mut trailer).await?;
                if tn == 0 || trailer == b"\r\n" || trailer == b"\n" {
                    break;
                }
            }
            return Ok(());
        }
        let mut remaining = size;
        while remaining > 0 {
            let want = buf.len().min(remaining);
            let n = reader
                .read(&mut buf[..want])
                .await
                .context("读取 chunk 数据失败")?;
            if n == 0 {
                bail!("origin 在 chunk 数据中间关闭了连接");
            }
            writer
                .write_all(&buf[..n])
                .await
                .context("回传 edge 响应体失败")?;
            writer.flush().await.context("回传 edge 响应体失败")?;
            remaining -= n;
        }
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .await
            .context("读取 chunk 结束符失败")?;
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize> {
    let text = String::from_utf8_lossy(line);
    let hex = text.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(hex, 16).with_context(|| format!("非法 chunk 大小: {hex:?}"))
}
