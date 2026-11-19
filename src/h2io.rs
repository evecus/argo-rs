//! 把 h2 的 RecvStream / SendStream 适配成 futures 的 AsyncRead / AsyncWrite。
//!
//! h2 crate 刻意不实现 std/futures 的 IO trait，只暴露 poll_data / send_data +
//! 流控窗口。这里实现两个包装器，既供 Cap'n Proto RPC（需要 futures IO）使用，
//! 也供 WebSocket 双向透传使用。

use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

fn other<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

/// 把 h2::RecvStream 包成 futures::AsyncRead。
pub struct H2Reader {
    inner: RecvStream,
    /// 当前 DATA 帧中尚未读完的字节。
    buf: Bytes,
    eof: bool,
}

impl H2Reader {
    pub fn new(inner: RecvStream) -> Self {
        Self {
            inner,
            buf: Bytes::new(),
            eof: false,
        }
    }
}

impl futures::AsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if !self.buf.is_empty() {
                let n = self.buf.len().min(buf.len());
                buf[..n].copy_from_slice(&self.buf[..n]);
                self.buf.advance(n);
                return Poll::Ready(Ok(n));
            }
            if self.eof {
                return Poll::Ready(Ok(0));
            }
            match self.inner.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => {
                    // 释放流控窗口，否则对端会停止发送。
                    let len = chunk.len();
                    if let Err(e) = self.inner.flow_control().release_capacity(len) {
                        return Poll::Ready(Err(other(e)));
                    }
                    self.buf = chunk;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(other(e)));
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(0));
                }
            }
        }
    }
}

/// 把 h2::SendStream<Bytes> 包成 futures::AsyncWrite。
pub struct H2Writer {
    inner: SendStream<Bytes>,
}

impl H2Writer {
    pub fn new(inner: SendStream<Bytes>) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> SendStream<Bytes> {
        self.inner
    }

    /// 结束 stream（发送 end_of_stream 的空 DATA 帧）。
    pub fn finish(&mut self) -> io::Result<()> {
        self.inner
            .send_data(Bytes::new(), true)
            .map_err(other)
    }
}

impl futures::AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // send_data 不需要预先 reserve_capacity：h2 会缓冲数据并隐式请求窗口。
        // 但为避免无界缓冲，先把待写长度登记为预留容量，再等窗口就绪。
        self.inner.reserve_capacity(data.len());
        match self.inner.poll_capacity(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2 stream closed",
                )));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Err(other(e)));
            }
            Poll::Ready(Some(Ok(capacity))) => {
                if capacity == 0 {
                    return Poll::Pending;
                }
                let n = capacity.min(data.len());
                let chunk = Bytes::copy_from_slice(&data[..n]);
                self.inner
                    .send_data(chunk, false)
                    .map_err(other)?;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 的 send_data 直接入队，由连接驱动发送，无需额外 flush。
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.finish())
    }
}
