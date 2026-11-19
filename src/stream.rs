/// QUIC 双向流的收/发两半容器。
///
/// quinn 的 RecvStream 已实现 futures::AsyncRead，SendStream 已实现 futures::AsyncWrite，
/// 各使用点直接取这两半分别 BufReader/BufWriter 包裹即可，无需合成单一 duplex。
pub struct QuinnDuplex {
    pub recv: quinn::RecvStream,
    pub send: quinn::SendStream,
}

impl QuinnDuplex {
    pub fn new(recv: quinn::RecvStream, send: quinn::SendStream) -> Self {
        Self { recv, send }
    }
}
