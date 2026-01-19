use serde::Deserialize;
use base64::Engine as _;
use rand::RngCore;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerCfg {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_public_url")]
    pub public_url: String,
    /// Base64-encoded 32-byte key used to sign/encrypt cookies
    pub cookie_key_base64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DbCfg {
    /// e.g. sqlite://dev.db or postgres://user:pass@host:5432/db
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerCfg,
    pub db: DbCfg,
}

fn default_bind_addr() -> String { "127.0.0.1:8080".to_string() }
fn default_public_url() -> String { "http://127.0.0.1:8080".to_string() }

impl AppConfig {
    pub fn load() -> anyhow::Result<Self> {
        // Load .env file if it exists
        let _ = dotenvy::dotenv();

        let settings = config::Config::builder()
            .add_source(config::Environment::default().separator("_"))
            .build()?;

        // Map flat env names to nested structure for convenience
        // APP_BIND_ADDR, APP_PUBLIC_URL, COOKIE_KEY_BASE64, DATABASE_URL
        let mut server = settings.get::<ServerCfg>("server").unwrap_or(ServerCfg {
            bind_addr: std::env::var("APP_BIND_ADDR").unwrap_or_else(|_| default_bind_addr()),
            public_url: std::env::var("APP_PUBLIC_URL").unwrap_or_else(|_| default_public_url()),
            cookie_key_base64: std::env::var("COOKIE_KEY_BASE64").unwrap_or_default(),
        });
        if server.cookie_key_base64.is_empty() {
            // Try from env flat var first
            if let Ok(v) = std::env::var("COOKIE_KEY_BASE64") {
                server.cookie_key_base64 = v;
            } else {
                // Generate a dev key (64 bytes) and keep it in-memory only
                let mut key = [0u8; 64];
                rand::rngs::OsRng.fill_bytes(&mut key);
                let b64 = base64::engine::general_purpose::STANDARD.encode(key);
                server.cookie_key_base64 = b64;
                tracing::warn!(
                    "COOKIE_KEY_BASE64 not provided; generated a temporary dev key. Sessions will be invalidated on restart."
                );
            }
        }

        let db = settings
            .get::<DbCfg>("db")
            .unwrap_or(DbCfg { url: std::env::var("DATABASE_URL")? });

        Ok(AppConfig { server, db })
    }
}

pub fn decode_cookie_key(b64: &str) -> anyhow::Result<[u8; 64]> {
    // tower-cookies expects 64 bytes key for Private (32 for signing + 32 for encryption)
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid COOKIE_KEY_BASE64: {}", e))?;
    if bytes.len() == 32 {
        // If user supplied 32 bytes, duplicate to make 64 (sign + encrypt)
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&bytes);
        out[32..].copy_from_slice(&bytes);
        return Ok(out);
    }
    if bytes.len() != 64 {
        return Err(anyhow::anyhow!(
            "COOKIE_KEY_BASE64 must decode to 32 or 64 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}
