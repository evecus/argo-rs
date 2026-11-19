use anyhow::{Context, Result};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use tracing::info;

/// 与官方一致：查 SRV `_[region-]v2-origintunneld._tcp.argotunnel.com`，再解析 target 的 A/AAAA。
/// 返回按 SRV 记录分组的 edge 地址（官方分为两个 region，最多取前 2 组）。
pub async fn discover_edges(region: Option<&str>) -> Result<Vec<Vec<SocketAddr>>> {
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

    let mut groups: Vec<Vec<SocketAddr>> = Vec::new();
    for record in srv.answers() {
        let srv = match &record.data {
            RData::SRV(srv) => srv,
            _ => continue,
        };
        let target = srv.target.to_string();
        let port = srv.port;
        let mut addrs = Vec::new();
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
        if !addrs.is_empty() {
            // IPv4 放前面：多数主机没有 IPv6 出口。
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
            groups.push(addrs);
        }
    }
    groups.truncate(2);

    anyhow::ensure!(!groups.is_empty(), "edge discovery 没有返回任何地址");
    info!(
        regions = groups.len(),
        count = groups.iter().map(|g| g.len()).sum::<usize>(),
        "edge 地址发现完成"
    );
    Ok(groups)
}

/// edge 地址池：把 HA 连接分散到不同 region、不同 IP。
pub struct EdgePool {
    regions: Vec<Vec<SocketAddr>>,
    used: Mutex<HashMap<usize, SocketAddr>>,
}

impl EdgePool {
    pub fn new(regions: Vec<Vec<SocketAddr>>) -> Self {
        assert!(!regions.is_empty() && regions.iter().all(|r| !r.is_empty()));
        Self { regions, used: Mutex::new(HashMap::new()) }
    }

    /// 为第 `conn` 条连接挑地址：按 conn 轮流落到各 region；
    /// 同 region 内优先避开其它连接正在使用的 IP；`attempt` 递增使重试换地址。
    pub fn pick(&self, conn: usize, attempt: usize) -> SocketAddr {
        let region = &self.regions[conn % self.regions.len()];
        let slot = conn / self.regions.len();
        let mut used = self.used.lock().unwrap();
        for k in 0..region.len() {
            let a = region[(slot + attempt + k) % region.len()];
            if !used.iter().any(|(&c, &u)| c != conn && u == a) {
                used.insert(conn, a);
                return a;
            }
        }
        let a = region[(slot + attempt) % region.len()];
        used.insert(conn, a);
        a
    }

    pub fn release(&self, conn: usize) {
        self.used.lock().unwrap().remove(&conn);
    }
}

pub async fn resolve_override(edge: &str) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(edge)
        .await
        .with_context(|| format!("解析 --edge {} 失败", edge))?
        .collect();
    anyhow::ensure!(!addrs.is_empty(), "--edge 没有解析出任何地址");
    Ok(addrs)
}
