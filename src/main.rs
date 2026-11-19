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
mod proxy;
mod quic;
mod rpc;
mod stream;
mod token;
mod tls;
mod web;

use anyhow::{Context, Result};
use clap::Parser;
use config::ConfigStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::LocalSet;
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
    /// 本地配置网页监听地址
    #[arg(long, default_value = "127.0.0.1:8080")]
    web_addr: SocketAddr,
    /// 路由配置文件路径
    #[arg(long, default_value = "routes.json")]
    config: PathBuf,
}

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

    let store = Arc::new(ConfigStore::load(&args.config)?);
    let web_store = store.clone();
    tokio::spawn(async move {
        if let Err(e) = web::serve(web_store, args.web_addr).await {
            warn!(%e, "配置页面启动失败");
        }
    });

    let edges = match &args.edge {
        Some(edge) => discovery::resolve_override(edge).await?,
        None => {
            let mut addrs = discovery::discover_edges(args.region.as_deref()).await?;
            if let Some(endpoint) = &tunnel_token.endpoint {
                info!(%endpoint, "token 中携带 endpoint，仍使用 SRV 发现结果");
            }
            // 就近优先：IPv4 放前面，减少 QUIC 初始包差异带来的兼容问题。
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
            addrs
        }
    };

    let use_quic = args.protocol != "http2";
    let allow_fallback = args.protocol == "auto";

    let local = LocalSet::new();
    local
        .run_until(async move {
            // 先按 QUIC 尝试所有 edge；auto 模式下全部失败再整体回退 HTTP/2。
            // 这与官方 protocolSelector(auto) 的语义一致：以 QUIC 起步，
            // 连接不可用时才切到 HTTP/2（TCP 7844）。
            let mut attempts: Vec<(bool, String)> = Vec::new();
            if use_quic {
                attempts.push((true, "QUIC".into()));
            }
            if allow_fallback || args.protocol == "http2" {
                attempts.push((false, "HTTP/2".into()));
            }

            let mut last_err = None;
            for (quic_mode, label) in attempts {
                info!(%label, "开始尝试边缘传输协议");
                // auto 模式下 QUIC 只试前 2 个 edge：UDP 被丢弃时每个握手有 5s
                // 超时，若对全部 40 个 edge 都试一遍才回退，等待时间不可接受。
                // 强制 --protocol quic 时仍会遍历全部 edge。
                let pool: Vec<_> = if quic_mode && allow_fallback {
                    edges.iter().take(2).collect()
                } else {
                    edges.iter().collect()
                };
                for edge in pool {
                    let result = if quic_mode {
                        quic::run(*edge, &tunnel_token, &secret, store.clone()).await
                    } else {
                        h2::run(*edge, &tunnel_token, &secret, store.clone()).await
                    };
                    match result {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            warn!(%e, %edge, %label, "该 edge 连接失败，尝试下一个");
                            last_err = Some(e);
                        }
                    }
                }
                if quic_mode && allow_fallback {
                    warn!("QUIC 连接失败，回退到 HTTP/2 (TCP 7844)");
                }
            }
            Err(last_err.unwrap_or_else(|| anyhow::anyhow!("没有可用的 edge 地址")))
        })
        .await
}
