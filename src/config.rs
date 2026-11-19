use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

/// 一条路由：把匹配到的 hostname + 路径前缀转发到本机端口。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub hostname: String,
    #[serde(default)]
    pub path_prefix: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutesConfig {
    #[serde(default = "default_port")]
    pub default_port: u16,
    #[serde(default)]
    pub routes: Vec<Route>,
}

fn default_port() -> u16 {
    8080
}

impl Default for RoutesConfig {
    fn default() -> Self {
        Self {
            default_port: default_port(),
            routes: vec![Route {
                hostname: "*".into(),
                path_prefix: "".into(),
                port: default_port(),
            }],
        }
    }
}

pub struct ConfigStore {
    path: std::path::PathBuf,
    inner: RwLock<RoutesConfig>,
}

impl ConfigStore {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let cfg = if path.exists() {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("读取配置失败: {}", path.display()))?;
            serde_json::from_str(&text).context("配置文件不是合法的 JSON")?
        } else {
            RoutesConfig::default()
        };
        Ok(Self {
            path,
            inner: RwLock::new(cfg),
        })
    }

    pub fn snapshot(&self) -> RoutesConfig {
        self.inner.read().expect("config lock poisoned").clone()
    }

    /// 网页配置更新：先写盘成功再替换内存，避免落盘失败导致状态不一致。
    pub fn replace(&self, cfg: RoutesConfig) -> Result<()> {
        let text = serde_json::to_string_pretty(&cfg)?;
        std::fs::write(&self.path, text)
            .with_context(|| format!("写入配置失败: {}", self.path.display()))?;
        *self.inner.write().expect("config lock poisoned") = cfg;
        Ok(())
    }

    /// 按 hostname（忽略大小写）和最长路径前缀匹配，找不到就用默认端口。
    pub fn resolve_port(&self, host: &str, path: &str) -> u16 {
        let cfg = self.snapshot();
        let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
        let mut best: Option<(&Route, usize)> = None;
        for route in &cfg.routes {
            let host_match = route.hostname == "*"
                || route.hostname.eq_ignore_ascii_case(&host);
            if !host_match {
                continue;
            }
            let prefix = route.path_prefix.trim_end_matches('/');
            if !prefix.is_empty() && !path.starts_with(prefix) {
                continue;
            }
            let score = if route.hostname == "*" { 0 } else { 100 } + prefix.len();
            if best.map_or(true, |(_, s)| score > s) {
                best = Some((route, score));
            }
        }
        best.map(|(r, _)| r.port).unwrap_or(cfg.default_port)
    }

    pub fn port_map(&self) -> HashMap<String, u16> {
        self.snapshot()
            .routes
            .iter()
            .map(|r| (r.hostname.clone(), r.port))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_wins() {
        let cfg = RoutesConfig {
            default_port: 9999,
            routes: vec![
                Route { hostname: "*".into(), path_prefix: "".into(), port: 1111 },
                Route { hostname: "example.com".into(), path_prefix: "".into(), port: 2222 },
                Route { hostname: "example.com".into(), path_prefix: "/api".into(), port: 3333 },
            ],
        };
        let store = ConfigStore {
            path: "/tmp/nonexistent-test-config.json".into(),
            inner: RwLock::new(cfg),
        };
        assert_eq!(store.resolve_port("example.com", "/api/v1"), 3333);
        assert_eq!(store.resolve_port("EXAMPLE.com", "/other"), 2222);
        assert_eq!(store.resolve_port("unknown.test", "/api/v1"), 1111);
    }
}
