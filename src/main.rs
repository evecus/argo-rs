// capnp 生成代码用 crate::<模块名>:: 绝对路径自引用，必须以确切名字挂在 crate 根。
// 生成代码含大量本实现用不到的 RPC 结构，统一压制其 lint 噪音。
#[allow(dead_code, unused_imports, unused_parens, non_camel_case_types, clippy::all)]
mod tunnelrpc_capnp {
    include!(concat!(env!("OUT_DIR"), "/tunnelrpc_capnp.rs"));
}
#[allow(dead_code, unused_imports, unused_parens, non_camel_case_types, clippy::all)]
mod quic_metadata_protocol_capnp {
    include!(concat!(env!("OUT_DIR"), "/quic_metadata_protocol_capnp.rs"));
}

mod config;
mod discovery;
mod h2;
mod h2io;
mod origin;
mod proxy;
mod quic;
mod rpc;
mod stream;
mod supervisor;
mod token;
mod tls;

use anyhow::{Context, Result};
use clap::Parser;
use config::ConfigStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;
use tokio::task::LocalSet;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use token::TunnelToken;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "argo-rs", version, about = "精简版 Cloudflare Tunnel 客户端")]
struct Args {
    /// 官方 Cloudflare Tunnel token（与 --token-file 二选一）
    #[arg(long)]
    token: Option<String>,
    /// 从文件读取 token
    #[arg(long)]
    token_file: Option<PathBuf>,
    /// 指定 edge region，例如 us
    #[arg(long)]
    region: Option<String>,
    /// 手动指定 edge 地址 host:port，跳过 SRV 发现
    #[arg(long)]
    edge: Option<String>,
    /// 边缘传输协议：auto（QUIC 优先，失败回退 HTTP/2，默认）、quic、http2
    #[arg(long, default_value = "auto", value_parser = ["auto", "quic", "http2"])]
    protocol: String,
    /// 到 edge 的并行隧道连接数（官方默认 4）
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u8).range(1..=8))]
    ha_connections: u8,
}

// 不再限制 worker 线程数：默认按可用 CPU 核数创建 tokio worker，
// 大流量场景下 HTTP/WebSocket 代理任务可以充分并行。
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let token_str = match (&args.token, &args.token_file) {
        (Some(t), _) => t.clone(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .with_context(|| format!("读取 token 文件失败: {}", path.display()))?,
        _ => anyhow::bail!("请提供 --token 或 --token-file"),
    };
    let tunnel_token = TunnelToken::parse(&token_str)?;
    let secret = tunnel_token.secret()?;
    info!(
        tunnel_id = %tunnel_token.tunnel_id,
        account_tag = %tunnel_token.account_tag,
        "token 解析成功"
    );

    // 路由由 Cloudflare 控制台管理：edge 注册成功后会推送 ingress 配置。
    let store = Arc::new(ConfigStore::new());

    let regions: Vec<Vec<SocketAddr>> = match &args.edge {
        Some(edge) => vec![discovery::resolve_override(edge).await?],
        None => {
            if let Some(endpoint) = &tunnel_token.endpoint {
                info!(%endpoint, "token 中携带 endpoint，仍使用 SRV 发现结果");
            }
            discovery::discover_edges(args.region.as_deref()).await?
        }
    };

    let protocol = match args.protocol.as_str() {
        "quic" => supervisor::Protocol::Quic,
        "http2" => supervisor::Protocol::Http2,
        _ => supervisor::Protocol::Auto,
    };
    let shared = Arc::new(supervisor::Shared {
        pool: discovery::EdgePool::new(regions),
        token: tunnel_token,
        secret,
        config: store,
        protocol,
        use_h2: AtomicBool::new(protocol == supervisor::Protocol::Http2),
        quic_fail_streak: AtomicU32::new(0),
    });
    let n = args.ha_connections as usize;

    let local = LocalSet::new();
    local
        .run_until(async move {
            let shutdown = CancellationToken::new();
            let handles: Vec<_> = (0..n)
                .map(|idx| {
                    tokio::task::spawn_local(
                        supervisor::run_connection(idx, shared.clone(), shutdown.clone())
                            .instrument(tracing::info_span!("conn", idx)),
                    )
                })
                .collect();
            info!(connections = n, "已启动隧道连接");

            wait_for_signal().await;
            info!("收到退出信号，正在注销全部连接");
            shutdown.cancel();
            if tokio::time::timeout(
                std::time::Duration::from_secs(10),
                futures::future::join_all(handles),
            )
            .await
            .is_err()
            {
                warn!("等待注销超时，强制退出");
            }
            Ok(())
        })
        .await
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
