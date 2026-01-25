use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn get_dstack_client() -> reqwest::Client {
    // Check for Unix socket path (production Phala)
    if let Ok(socket_path) = std::env::var("DSTACK_SOCKET") {
        tracing::info!(socket_path = %socket_path, "Using Unix socket for dstack");
        return reqwest::Client::builder()
            .unix_socket(std::path::Path::new(&socket_path))
            .build()
            .expect("Failed to build Unix socket client");
    }

    // Fall back to HTTP endpoint (local dev with simulator)
    tracing::info!("Using HTTP endpoint for dstack");
    reqwest::Client::new()
}

fn get_dstack_url() -> String {
    // For Unix socket, use a dummy localhost URL (the socket connector will handle it)
    match std::env::var("DSTACK_SOCKET") {
        Ok(socket_path) => {
            tracing::info!(socket_path = %socket_path, "DSTACK_SOCKET is set, using localhost URL");
            return "http://localhost".to_string();
        }
        Err(e) => {
            tracing::warn!(error = ?e, "DSTACK_SOCKET not set");
        }
    }

    // For HTTP, use configurable endpoint
    let endpoint = std::env::var("DSTACK_ENDPOINT")
        .unwrap_or_else(|_| "http://simulator:8090".to_string());
    tracing::info!(endpoint = %endpoint, "Using HTTP endpoint");
    endpoint
}

/// Response from dstack GetQuote endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    /// Base64-encoded TDX quote
    pub quote: String,
    /// Optional event log
    #[serde(rename = "eventLog")]
    pub event_log: Option<String>,
    #[serde(rename = "vmConfig")]
    pub vm_config: Option<String>,
}

/// Response from dstack DeriveKey endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedKey {
    /// Hex-encoded derived key
    pub key: String,
}

pub struct DstackClient;

impl DstackClient {
    pub fn new() -> Self {
        Self
    }

    /// Generate TDX attestation quote for the given data
    ///
    /// If data > 64 bytes, it will be hashed with SHA256
    /// If data <= 64 bytes, it will be zero-padded to 64 bytes
    pub async fn get_quote(&self, report_data: &[u8]) -> Result<Quote> {
        let hex_data = if report_data.len() > 64 {
            // Hash if too long
            let mut hasher = Sha256::new();
            hasher.update(report_data);
            hex::encode(hasher.finalize())
        } else {
            // Pad with zeros to 64 bytes
            let mut padded = vec![0u8; 64];
            padded[..report_data.len()].copy_from_slice(report_data);
            hex::encode(padded)
        };

        // Use tappd-simulator HTTP API format
        #[derive(Serialize)]
        struct GetQuoteRequest {
            #[serde(rename = "reportData")]
            report_data: String,
        }

        let request_body = GetQuoteRequest {
            report_data: format!("0x{}", hex_data),
        };

        let json_param = serde_json::to_string(&request_body)?;
        let url = format!("{}/prpc/Tappd.TdxQuote?json={}", get_dstack_url(), urlencoding::encode(&json_param));

        let client = get_dstack_client();
        let response = client
            .get(&url)
            .send()
            .await
            .context("Failed to send request to dstack")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("GetQuote failed: {}", error_text);
        }

        let quote: Quote = response
            .json()
            .await
            .context("Failed to parse GetQuote response")?;

        Ok(quote)
    }

    /// Derive a key from dstack KMS
    pub async fn derive_key(&self, path: &str) -> Result<DerivedKey> {
        #[derive(Serialize)]
        struct DeriveKeyRequest<'a> {
            path: &'a str,
        }

        let request_body = DeriveKeyRequest { path };
        let json_param = serde_json::to_string(&request_body)?;
        let url = format!("{}/prpc/Tappd.DeriveKey?json={}", get_dstack_url(), urlencoding::encode(&json_param));

        let client = get_dstack_client();
        let response = client
            .get(&url)
            .send()
            .await
            .context("Failed to send request to dstack")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("DeriveKey failed: {}", error_text);
        }

        let key: DerivedKey = response
            .json()
            .await
            .context("Failed to parse DeriveKey response")?;

        Ok(key)
    }
}

impl Default for DstackClient {
    fn default() -> Self {
        Self::new()
    }
}
