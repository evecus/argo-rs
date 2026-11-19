use anyhow::{Context, Result};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use std::net::{IpAddr, SocketAddr};
use tracing::info;

/// 与官方一致：查 SRV `_[region-]v2-origintunneld._tcp.argotunnel.com`，再解析 target 的 A/AAAA。
pub async fn discover_edges(region: Option<&str>) -> Result<Vec<SocketAddr>> {
    let service = match region {
        Some(r) if !r.is_empty() => format!("_{}-v2-origintunneld._tcp.argotunnel.com", r),
        _ => "_v2-origintunneld._tcp.argotunnel.com".to_string(),
    };

    let resolver = TokioResolver::builder_tokio()
        .context("无法创建系统 DNS resolver")?
        .build()
        .context("构建系统 DNS resolver 失败")?;
    let srv = resolver
        .srv_lookup(service.clone())
        .await
        .with_context(|| format!("SRV 查询失败: {}", service))?;

    let mut addrs = Vec::new();
    for record in srv.answers() {
        let srv = match &record.data {
            RData::SRV(srv) => srv,
            _ => continue,
        };
        let target = srv.target.to_string();
        let port = srv.port;
        // A 记录
        if let Ok(lookup) = resolver.ipv4_lookup(target.clone()).await {
            let answers: &[hickory_resolver::proto::rr::Record] = lookup.answers();
            for ans in answers {
                if let RData::A(a) = &ans.data {
                    addrs.push(SocketAddr::new(IpAddr::V4(a.0), port));
                }
            }
        }
        // AAAA 记录
        if let Ok(lookup) = resolver.ipv6_lookup(target.clone()).await {
            let answers: &[hickory_resolver::proto::rr::Record] = lookup.answers();
            for ans in answers {
                if let RData::AAAA(a) = &ans.data {
                    addrs.push(SocketAddr::new(IpAddr::V6(a.0), port));
                }
            }
        }
    }

    anyhow::ensure!(!addrs.is_empty(), "edge discovery 没有返回任何地址");
    info!(count = addrs.len(), "edge 地址发现完成");
    Ok(addrs)
}

pub async fn resolve_override(edge: &str) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(edge)
        .await
        .with_context(|| format!("解析 --edge {} 失败", edge))?
        .collect();
    anyhow::ensure!(!addrs.is_empty(), "--edge 没有解析出任何地址");
    Ok(addrs)
}
