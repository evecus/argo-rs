use crate::config::{ConfigStore, RoutesConfig};
use anyhow::Result;
use axum::extract::{Form, State};
use axum::response::{Html, Redirect};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Deserialize)]
struct ConfigForm {
    config: String,
}

pub async fn serve(config: Arc<ConfigStore>, addr: SocketAddr) -> Result<()> {
    let app = Router::new()
        .route("/", get(index).post(save))
        .with_state(config);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info_listener(&addr);
    axum::serve(listener, app).await?;
    Ok(())
}

fn info_listener(addr: &SocketAddr) {
    tracing::info!("配置页面已启动: http://{}", addr);
}

async fn index(State(config): State<Arc<ConfigStore>>) -> Html<String> {
    let snapshot = config.snapshot();
    let json = serde_json::to_string_pretty(&snapshot).unwrap_or_default();
    Html(format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>argo-rs 路由配置</title>
<style>body{{font-family:system-ui;margin:2rem;max-width:800px}}textarea{{width:100%;height:320px;font-family:monospace}}button{{padding:.6rem 1.2rem;margin-top:1rem}}</style>
</head><body>
<h1>argo-rs 路由配置</h1>
<p>hostname 可用 <code>*</code> 表示默认；path_prefix 为空表示匹配全部路径。修改后点保存即时生效（写入配置文件）。</p>
<form method="post"><textarea name="config">{}</textarea><br><button type="submit">保存配置</button></form>
<h2>当前路由</h2><ul>{}</ul>
</body></html>"#,
        escape_html(&json),
        snapshot
            .routes
            .iter()
            .map(|r| format!("<li><code>{}</code>{} → 127.0.0.1:{}</li>", escape_html(&r.hostname), escape_html(&r.path_prefix), r.port))
            .collect::<Vec<_>>()
            .join("")
    ))
}

async fn save(
    State(config): State<Arc<ConfigStore>>,
    Form(form): Form<ConfigForm>,
) -> std::result::Result<Redirect, (axum::http::StatusCode, String)> {
    let parsed: RoutesConfig = serde_json::from_str(&form.config)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("JSON 解析失败: {}", e)))?;
    config.replace(parsed).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存失败: {}", e),
        )
    })?;
    Ok(Redirect::temporary("/"))
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
