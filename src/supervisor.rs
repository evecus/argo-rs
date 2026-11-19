//! HA 连接监督：每条连接一个独立任务，各自带 connIndex、各自断线退避重连。
//!
//! 对照官方 cloudflared supervisor：
//!   - 连接分散到不同 region / 不同 IP（见 `EdgePool`）
//!   - 启动时错峰（官方 registrationInterval = 1s）
//!   - auto 协议：QUIC 在注册前连续失败 2 次，整体切到 HTTP/2 并保持

use crate::config::ConfigStore;
use crate::discovery::EdgePool;
use crate::token::TunnelToken;
use crate::{h2, quic};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    Auto,
    Quic,
    Http2,
}

pub struct Shared {
    pub pool: EdgePool,
    pub token: TunnelToken,
    pub secret: Vec<u8>,
    pub config: Arc<ConfigStore>,
    pub protocol: Protocol,
    /// auto 模式下是否已整体回退到 HTTP/2。
    pub use_h2: AtomicBool,
    /// 连续的 “QUIC 注册前失败” 次数，任意一条 QUIC 注册成功即清零。
    pub quic_fail_streak: AtomicU32,
}

const QUIC_FAILS_BEFORE_FALLBACK: u32 = 2;
const STAGGER: Duration = Duration::from_secs(1);
const MAX_BACKOFF_SECS: u64 = 60;

/// 必须在 LocalSet 内运行（capnp-rpc 依赖 spawn_local）。仅在 `shutdown` 后返回。
pub async fn run_connection(idx: usize, shared: Arc<Shared>, shutdown: CancellationToken) {
    if idx > 0 {
        tokio::select! {
            _ = tokio::time::sleep(STAGGER * idx as u32) => {}
            _ = shutdown.cancelled() => return,
        }
    }

    let mut failures: u32 = 0;
    let mut attempt: usize = 0;
    while !shutdown.is_cancelled() {
        let edge = shared.pool.pick(idx, attempt);
        attempt += 1;

        let use_quic = match shared.protocol {
            Protocol::Quic => true,
            Protocol::Http2 => false,
            Protocol::Auto => !shared.use_h2.load(Ordering::Relaxed),
        };

        let registered = AtomicBool::new(false);
        let on_registered = || {
            registered.store(true, Ordering::Relaxed);
            if use_quic {
                shared.quic_fail_streak.store(0, Ordering::Relaxed);
            }
        };

        let result = if use_quic {
            quic::run(edge, idx as u8, &shared.token, &shared.secret, shared.config.clone(), shutdown.clone(), &on_registered).await
        } else {
            h2::run(edge, idx as u8, &shared.token, &shared.secret, shared.config.clone(), shutdown.clone(), &on_registered).await
        };
        shared.pool.release(idx);

        let was_registered = registered.load(Ordering::Relaxed);
        match result {
            Ok(()) => break, // 只有收到退出信号才会 Ok
            Err(e) => warn!(error = format!("{:#}", e), %edge, "连接中断，准备重连"),
        }
        if shutdown.is_cancelled() {
            break;
        }

        if was_registered {
            failures = 0;
        } else {
            failures += 1;
            if use_quic && shared.protocol == Protocol::Auto {
                let n = shared.quic_fail_streak.fetch_add(1, Ordering::Relaxed) + 1;
                if n >= QUIC_FAILS_BEFORE_FALLBACK && !shared.use_h2.swap(true, Ordering::Relaxed) {
                    warn!("QUIC 连续失败，全部连接回退到 HTTP/2 (TCP 7844)");
                }
            }
        }

        // 指数退避 1s,2s,4s…最多 60s，外加 <1s 抖动避免 4 条连接同时重连。
        let secs = (1u64 << failures.min(6)).min(MAX_BACKOFF_SECS);
        let jitter = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_millis() as u64)
            .unwrap_or(0);
        let delay = Duration::from_millis(secs * 1000 + jitter);
        info!(?delay, "等待后重连");
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.cancelled() => break,
        }
    }
    info!("连接任务已退出");
}
