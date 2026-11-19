//! 远程下发的 ingress 配置（Cloudflare 控制台里配置的 Public Hostname 路由）。
//!
//! edge 在隧道注册后通过 `updateConfiguration`（QUIC: capnp RPC；HTTP/2: `update-configuration`
//! 请求）推送 JSON：
//! `{"ingress":[{"hostname":"a.example.com","path":"^/api","service":"http://localhost:3000",
//!   "originRequest":{"httpHostHeader":"x"}}, {"service":"http_status:404"}], "originRequest":{...}}`
//! 语义与官方 cloudflared 一致：按顺序取第一条匹配规则，都不匹配则用最后一条；
//! 未收到任何配置前，所有请求返回 503（与官方默认一致）。
//!
//! 仅支持 `http://host[:port]` 与 `http_status:NNN`；其它 service（https/unix/tcp/ssh…）
//! 会在匹配到时返回 502 并打日志。

use anyhow::{anyhow, bail, Result};
use regex::Regex;
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Service {
    Http { host: String, port: u16 },
    Status(u16),
    Unsupported(String),
}

/// 路由解析结果：转发目标 + 可选的 Host 头覆盖（originRequest.httpHostHeader）。
#[derive(Debug, Clone)]
pub struct Target {
    pub service: Service,
    pub host_header: Option<String>,
}

#[derive(Debug)]
struct Rule {
    hostname: String,
    path: Option<Regex>,
    service: Service,
    host_header: Option<String>,
}

impl Rule {
    fn matches(&self, host: &str, path: &str) -> bool {
        let host_ok = self.hostname.is_empty()
            || self.hostname == "*"
            || self.hostname == host
            || (self.hostname.starts_with("*.") && host.ends_with(&self.hostname[1..]));
        host_ok && self.path.as_ref().map_or(true, |re| re.is_match(path))
    }
}

struct State {
    version: i32,
    rules: Arc<Vec<Rule>>,
}

pub struct ConfigStore {
    inner: RwLock<State>,
}

#[derive(Deserialize, Default)]
struct OriginRequestJson {
    #[serde(default, rename = "httpHostHeader")]
    http_host_header: Option<String>,
}

#[derive(Deserialize)]
struct RuleJson {
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    service: String,
    #[serde(default, rename = "originRequest")]
    origin_request: Option<OriginRequestJson>,
}

#[derive(Deserialize)]
struct RemoteJson {
    #[serde(default)]
    ingress: Vec<RuleJson>,
    #[serde(default, rename = "originRequest")]
    origin_request: Option<OriginRequestJson>,
}

fn default_rules() -> Vec<Rule> {
    vec![Rule {
        hostname: String::new(),
        path: None,
        service: Service::Status(503),
        host_header: None,
    }]
}

fn parse_service(s: &str) -> Result<Service> {
    if let Some(code) = s.strip_prefix("http_status:") {
        let code: u16 = code.trim().parse().map_err(|_| anyhow!("非法的 HTTP 状态码: {}", code))?;
        if !(100..=999).contains(&code) {
            bail!("非法的 HTTP 状态码: {}", code);
        }
        return Ok(Service::Status(code));
    }
    if s.starts_with("http://") {
        let uri: http::Uri = s.parse().map_err(|e| anyhow!("非法的 service URL {}: {}", s, e))?;
        let host = uri
            .host()
            .ok_or_else(|| anyhow!("service URL 缺少主机: {}", s))?
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        let port = uri.port_u16().unwrap_or(80);
        return Ok(Service::Http { host, port });
    }
    Ok(Service::Unsupported(s.to_string()))
}

fn parse_rules(raw: &[u8]) -> Result<Vec<Rule>> {
    let remote: RemoteJson = serde_json::from_slice(raw).map_err(|e| anyhow!("配置不是合法 JSON: {}", e))?;
    let global_host = remote.origin_request.and_then(|o| o.http_host_header).filter(|h| !h.is_empty());
    let mut rules = Vec::with_capacity(remote.ingress.len());
    for r in remote.ingress {
        let path = match r.path.as_deref() {
            Some(p) if !p.is_empty() => {
                Some(Regex::new(p).map_err(|e| anyhow!("非法的 path 正则 {}: {}", p, e))?)
            }
            _ => None,
        };
        let host_header = r
            .origin_request
            .and_then(|o| o.http_host_header)
            .filter(|h| !h.is_empty())
            .or_else(|| global_host.clone());
        rules.push(Rule {
            hostname: r.hostname.unwrap_or_default().to_ascii_lowercase(),
            path,
            service: parse_service(&r.service)?,
            host_header,
        });
    }
    Ok(rules)
}

/// 去掉 Host 里的端口并转小写（支持 `[::1]:80` 形式）。
fn normalize_host(host: &str) -> String {
    let h = host.trim();
    let h = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if let Some((name, port)) = h.rsplit_once(':') {
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !name.contains(':') {
            name
        } else {
            h
        }
    } else {
        h
    };
    h.to_ascii_lowercase()
}

impl ConfigStore {
    /// 初始状态：没有任何配置，所有请求 503，直到 edge 推送远程配置。
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(State {
                version: -1,
                rules: Arc::new(default_rules()),
            }),
        }
    }

    /// 应用 edge 推送的配置。返回 (当前已应用版本, 错误信息)。
    /// 版本不高于当前版本时忽略；解析失败时保留旧配置并返回错误（与官方一致）。
    pub fn update(&self, version: i32, raw: &[u8]) -> (i32, Option<String>) {
        let mut state = self.inner.write().expect("config lock poisoned");
        if state.version >= version {
            return (state.version, None);
        }
        match parse_rules(raw) {
            Ok(mut rules) => {
                if rules.is_empty() {
                    rules = default_rules();
                }
                for r in &rules {
                    if let Service::Unsupported(s) = &r.service {
                        warn!(service = %s, hostname = %r.hostname, "该 ingress service 不受支持（仅支持 http:// 与 http_status:），匹配时将返回 502");
                    }
                }
                info!(version, rules = rules.len(), "已应用远程配置");
                state.version = version;
                state.rules = Arc::new(rules);
                (version, None)
            }
            Err(e) => {
                let msg = format!("{:#}", e);
                warn!(version, error = %msg, "远程配置应用失败，保留旧配置");
                (state.version, Some(msg))
            }
        }
    }

    /// 按顺序找第一条匹配规则；都不匹配则用最后一条（官方语义）。
    pub fn resolve(&self, host: &str, path_and_query: &str) -> Target {
        let host = normalize_host(host);
        let path = path_and_query.split('?').next().unwrap_or("/");
        let rules = self.inner.read().expect("config lock poisoned").rules.clone();
        let rule = rules
            .iter()
            .find(|r| r.matches(&host, path))
            .or_else(|| rules.last())
            .expect("rules never empty");
        Target {
            service: rule.service.clone(),
            host_header: rule.host_header.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"{
      "ingress": [
        {"hostname":"api.example.com","path":"^/v1/","service":"http://localhost:3000"},
        {"hostname":"*.example.com","service":"http://127.0.0.1:8080","originRequest":{"httpHostHeader":"internal"}},
        {"service":"http_status:404"}
      ],
      "warp-routing": {"enabled": false}
    }"#;

    #[test]
    fn first_match_wins_and_fallback() {
        let s = ConfigStore::new();
        assert_eq!(s.resolve("a.test", "/").service, Service::Status(503));
        assert_eq!(s.update(1, CFG.as_bytes()), (1, None));
        assert_eq!(
            s.resolve("API.example.com:443", "/v1/x?y=1").service,
            Service::Http { host: "localhost".into(), port: 3000 }
        );
        let t = s.resolve("api.example.com", "/other");
        assert_eq!(t.service, Service::Http { host: "127.0.0.1".into(), port: 8080 });
        assert_eq!(t.host_header.as_deref(), Some("internal"));
        assert_eq!(s.resolve("other.org", "/").service, Service::Status(404));
    }

    #[test]
    fn stale_or_bad_config_keeps_old() {
        let s = ConfigStore::new();
        s.update(5, CFG.as_bytes());
        assert_eq!(s.update(5, b"{}"), (5, None));
        let (v, err) = s.update(6, b"not json");
        assert_eq!(v, 5);
        assert!(err.is_some());
        assert_eq!(s.resolve("other.org", "/").service, Service::Status(404));
    }
}
