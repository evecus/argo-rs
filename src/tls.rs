use anyhow::{Context, Result};
use rustls::RootCertStore;
use std::sync::Arc;

/// 官方 tlsconfig.CreateTunnelConfig 的做法：系统根 + 内置 Cloudflare Origin CA 根。
pub fn build_client_config(alpn: Vec<Vec<u8>>) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut cursor = std::io::Cursor::new(include_bytes!("cf_roots.pem"));
    for cert in rustls_pemfile::certs(&mut cursor) {
        let cert = cert.context("解析内置 Cloudflare 根证书失败")?;
        roots.add(cert).context("加入 Cloudflare 根证书失败")?;
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Ok(Arc::new(config))
}
