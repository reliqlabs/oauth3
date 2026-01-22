use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Use HTTP endpoint for simulator (works in both local dev and production)
// In production Phala Cloud, this will be the actual dstack socket endpoint
// For local dev with tappd-simulator, use HTTP
const DSTACK_ENDPOINT: &str = "http://simulator:8090";

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
        let url = format!("{}/prpc/Tappd.TdxQuote?json={}", DSTACK_ENDPOINT, urlencoding::encode(&json_param));

        let client = reqwest::Client::new();
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
        let url = format!("{}/prpc/Tappd.DeriveKey?json={}", DSTACK_ENDPOINT, urlencoding::encode(&json_param));

        let client = reqwest::Client::new();
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
