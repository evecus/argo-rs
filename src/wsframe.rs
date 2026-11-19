//! 最小 WebSocket 帧编解码：edge（WS 客户端）↔ 本地 TCP 服务的裸字节隧道。
//!
//! 对齐官方 websocket/connection.go 的 wsutil.ReadClientBinary/WriteServerBinary：
//! 客户端帧必带掩码，服务端帧不带掩码；ping → pong，close → 结束隧道。
//! 只处理 edge 发起的连接，不实现 WS 握手（握手头由 proxy.rs / h2.rs 构造）。

use anyhow::{bail, Context, Result};
use futures::io::{AsyncRead, AsyncReadExt as FuturesReadExt, AsyncWrite, AsyncWriteExt as FuturesWriteExt};
use tokio::io::{AsyncReadExt as TokioReadExt, AsyncWriteExt as TokioWriteExt};
use tracing::debug;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// 单条 WS 消息上限，避免异常帧把内存打满。
const MAX_MESSAGE: usize = 1024 * 1024;

/// 由 Sec-WebSocket-Key 计算 Sec-WebSocket-Accept（RFC6455）。
pub fn accept_key(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let digest = hasher.finalize();
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest)
}

enum Frame {
    /// 数据消息（分片已重组）。
    Data(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close,
}

/// 从 futures AsyncRead 上逐帧读取 edge 发来的 WS 帧。
/// 内部缓冲保留未消费字节：tokio::select! 取消读帧 future 时不会丢数据。
struct FrameReader<R> {
    inner: R,
    buf: Vec<u8>,
    fragments: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            fragments: Vec::new(),
        }
    }

    async fn fill(&mut self, n: usize) -> Result<()> {
        let mut tmp = [0u8; 8192];
        while self.buf.len() < n {
            let read = self
                .inner
                .read(&mut tmp)
                .await
                .context("读取 edge WebSocket 帧失败")?;
            if read == 0 {
                bail!("edge 在 WebSocket 帧中间关闭了连接");
            }
            self.buf.extend_from_slice(&tmp[..read]);
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        self.buf.drain(..n).collect()
    }

    async fn next_frame(&mut self) -> Result<Frame> {
        loop {
            self.fill(2).await?;
            let header = self.take(2);
            let fin = header[0] & 0x80 != 0;
            let opcode = header[0] & 0x0f;
            let masked = header[1] & 0x80 != 0;
            let mut len = (header[1] & 0x7f) as u64;
            if len == 126 {
                self.fill(2).await?;
                let ext = self.take(2);
                len = u16::from_be_bytes([ext[0], ext[1]]) as u64;
            } else if len == 127 {
                self.fill(8).await?;
                let ext = self.take(8);
                len = u64::from_be_bytes(ext.try_into().unwrap());
            }
            if len > MAX_MESSAGE as u64 {
                bail!("edge WebSocket 帧过大: {len}");
            }
            if !masked {
                bail!("edge WebSocket 帧缺少掩码");
            }
            self.fill(4).await?;
            let mask = self.take(4);
            let payload_len = len as usize;
            self.fill(payload_len).await?;
            let mut payload = self.take(payload_len);
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
            match opcode {
                0x0..=0x2 => {
                    self.fragments.extend_from_slice(&payload);
                    if self.fragments.len() > MAX_MESSAGE {
                        bail!("edge WebSocket 消息超过上限");
                    }
                    if fin {
                        return Ok(Frame::Data(std::mem::take(&mut self.fragments)));
                    }
                }
                0x8 => return Ok(Frame::Close),
                0x9 => return Ok(Frame::Ping(payload)),
                0xA => return Ok(Frame::Pong),
                _ => bail!("未知的 WebSocket opcode: {opcode:#x}"),
            }
        }
    }
}

/// 向 futures AsyncWrite 写未掩码的服务端帧。
struct FrameWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner }
    }

    async fn frame(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut header = [0u8; 10];
        header[0] = 0x80 | opcode;
        let head_len = if payload.len() < 126 {
            header[1] = payload.len() as u8;
            2
        } else if payload.len() <= u16::MAX as usize {
            header[1] = 126;
            header[2..4].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            4
        } else {
            header[1] = 127;
            header[2..10].copy_from_slice(&(payload.len() as u64).to_be_bytes());
            10
        };
        self.inner
            .write_all(&header[..head_len])
            .await
            .context("写 WebSocket 帧头失败")?;
        self.inner
            .write_all(payload)
            .await
            .context("写 WebSocket 帧体失败")?;
        Ok(())
    }

    async fn write_binary(&mut self, data: &[u8]) -> Result<()> {
        self.frame(0x2, data).await
    }

    async fn write_pong(&mut self, data: &[u8]) -> Result<()> {
        self.frame(0xA, data).await
    }

    async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await.context("刷新 WebSocket 帧失败")
    }
}

enum Outbound {
    Tcp(usize),
    Pong(Vec<u8>),
}

/// 双向泵：WS 帧 ↔ 裸 TCP 字节。
/// 单循环 + select 避免同时可变借用 writer：ping 的 pong 通过 channel
/// 汇入出站分支，与 TCP 数据统一经 FrameWriter 写出。
pub async fn pump<R, W, T>(reader: R, writer: W, tcp: T) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut frame_reader = FrameReader::new(reader);
    let mut frame_writer = FrameWriter::new(writer);
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let mut tcp_buf = vec![0u8; 16 * 1024];

    loop {
        tokio::select! {
            frame = frame_reader.next_frame() => {
                match frame? {
                    Frame::Data(data) => {
                        tcp_write.write_all(&data).await.context("写入本地 TCP 服务失败")?;
                    }
                    Frame::Ping(payload) => {
                        if pong_tx.try_send(payload).is_err() {
                            debug!("pong 队列已满，丢弃一个 ping");
                        }
                    }
                    Frame::Pong => {}
                    Frame::Close => break,
                }
            }
            outbound = async {
                tokio::select! {
                    n = tcp_read.read(&mut tcp_buf) => Ok::<_, anyhow::Error>(Outbound::Tcp(n?)),
                    pong = pong_rx.recv() => Ok(Outbound::Pong(pong.unwrap_or_default())),
                }
            } => {
                match outbound? {
                    Outbound::Tcp(0) => break,
                    Outbound::Tcp(n) => {
                        frame_writer.write_binary(&tcp_buf[..n]).await?;
                    }
                    Outbound::Pong(payload) => {
                        frame_writer.write_pong(&payload).await?;
                    }
                }
                frame_writer.flush().await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_accept_key() {
        // RFC6455 §1.3 的已知向量。
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn masked_client_frame_roundtrip() {
        let payload = b"hello";
        let mask = [1u8, 2, 3, 4];
        let mut wire = vec![0x81, 0x85];
        wire.extend_from_slice(&mask);
        wire.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let mut reader = FrameReader::new(futures::io::Cursor::new(wire));
        match reader.next_frame().await.unwrap() {
            Frame::Data(data) => assert_eq!(data, payload),
            _ => panic!("期望数据帧"),
        }

        let mut out = Vec::new();
        let mut writer = FrameWriter::new(&mut out);
        writer.write_binary(b"world").await.unwrap();
        assert_eq!(out, [0x82, 0x05, b'w', b'o', b'r', b'l', b'd']);
    }
}
