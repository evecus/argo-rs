use crate::config::ConfigStore;
use crate::proxy;
use crate::rpc::Registration;
use crate::stream::QuinnDuplex;
use crate::token::TunnelToken;
use crate::tls;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

pub async fn run(
    edge: SocketAddr,
    token: &TunnelToken,
    secret: &[u8],
    config: Arc<ConfigStore>,
) -> Result<()> {
    let tls_config = tls::build_client_config(vec![b"argotunnel".to_vec()])?;
    let quic_client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("构造 QUIC TLS 配置失败")?,
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?).context("创建 QUIC endpoint 失败")?;
    endpoint.set_default_client_config(quic_client_config);

    info!(%edge, "连接 Cloudflare edge (QUIC)");
    let connecting = endpoint
        .connect(edge, "quic.cftunnel.com")
        .with_context(|| format!("QUIC 拨号失败: {}", edge))?;
    // 官方 dialTimeout 约 5s：UDP 被丢弃时尽快失败，auto 模式才能及时回退 H2，
    // 否则 quinn 默认 30s 超时 × 40 edge 会让回退等待 20 分钟。
    let connection = tokio::time::timeout(std::time::Duration::from_secs(5), connecting)
        .await
        .context("QUIC 握手超时")?
        .context("QUIC 握手失败")?;

    // 官方 quicConnection.Serve：第一条双向流固定作为控制流。
    let (send, recv) = connection.open_bi().await.context("打开控制流失败")?;
    let (registration, info) = Registration::register(recv, send, token, secret, 0).await?;
    info!(
        location = %info.location,
        connection_id = %info.uuid.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        "隧道注册成功"
    );

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let edge_closed;
    loop {
        tokio::select! {
            stream = connection.accept_bi() => {
                let (send, recv) = match stream {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(%e, "edge 关闭了 QUIC 连接");
                        edge_closed = true;
                        break;
                    }
                };
                let cfg = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = proxy::serve_data_stream(QuinnDuplex::new(recv, send), cfg).await {
                        warn!(%e, "处理数据流转代理请求失败");
                    }
                });
            }
            _ = &mut ctrl_c => {
                info!("收到 Ctrl-C，正在注销隧道连接");
                if let Err(e) = registration.unregister().await {
                    warn!(error = format!("{:#}", e), "注销失败");
                }
                edge_closed = false;
                break;
            }
        }
    }

    registration.shutdown().await?;
    connection.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;
    if edge_closed {
        anyhow::bail!("与 edge 的连接已断开");
    }
    Ok(())
}
