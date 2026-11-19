use anyhow::{Context, Result};
use base64::Engine;
use serde::Deserialize;
use uuid::Uuid;

/// 官方 cloudflared 的 TunnelToken：JSON 字段故意是单字母缩写。
/// token 字符串本身 = base64.StdEncoding(JSON)
#[derive(Debug, Clone, Deserialize)]
pub struct TunnelToken {
    #[serde(rename = "a")]
    pub account_tag: String,
    /// JSON 里的 s 是 Go []byte 的序列化形式，即标准 base64
    #[serde(rename = "s")]
    pub secret_b64: String,
    #[serde(rename = "t")]
    pub tunnel_id: Uuid,
    #[serde(rename = "e", default)]
    pub endpoint: Option<String>,
}

impl TunnelToken {
    pub fn parse(input: &str) -> Result<Self> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(input.trim())
            .context("token 不是合法的 base64")?;
        let token: Self = serde_json::from_slice(&raw).context("token 解码后不是合法的 JSON")?;
        anyhow::ensure!(!token.account_tag.is_empty(), "token 缺少 account tag");
        Ok(token)
    }

    pub fn secret(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.secret_b64)
            .context("tunnel secret 不是合法的 base64")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_real_shape() {
        // 结构与官方一致：a=accountTag, s=base64(secret), t=uuid
        let json = r#"{"a":"abc123","s":"c2VjcmV0","t":"00000000-0000-0000-0000-000000000001"}"#;
        let token_str = base64::engine::general_purpose::STANDARD.encode(json);
        let token = TunnelToken::parse(&token_str).unwrap();
        assert_eq!(token.account_tag, "abc123");
        assert_eq!(token.secret().unwrap(), b"secret");
        assert_eq!(token.tunnel_id.to_string(), "00000000-0000-0000-0000-000000000001");
    }
}
