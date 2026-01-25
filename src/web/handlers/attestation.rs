use axum::{http::StatusCode, response::IntoResponse, Json};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::attestation::DstackClient;
use dstack_verifier::{AttestationVerifier, AttestationResponse as DstackAttestation, InfoResponse as DstackInfo};

/// Standard Phala Cloud attestation response
/// Follows pattern from https://docs.phala.com/phala-cloud/phala-cloud-user-guides/building-with-tee/generate-ra-report
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// TDX quote proving TEE execution
    pub quote: String,
    /// Optional event log
    #[serde(rename = "eventLog", skip_serializing_if = "Option::is_none")]
    pub event_log: Option<String>,
    /// Optional VM configuration
    #[serde(rename = "vmConfig", skip_serializing_if = "Option::is_none")]
    pub vm_config: Option<String>,
}

/// Application info response for code verification
/// Recommended by Phala Cloud docs alongside /attestation
#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResponse {
    /// Application version
    pub version: String,
    /// Application name
    pub name: String,
    /// Build timestamp or commit hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_info: Option<String>,
}

/// GET /attestation
///
/// Returns TDX attestation quote proving this code is running in a TEE.
/// The quote includes the application configuration hash in reportData.
///
/// Clients can verify:
/// 1. Hardware authenticity (via Intel TDX verification)
/// 2. Code integrity (by hashing /info response and comparing to reportData)
pub async fn attestation() -> Result<impl IntoResponse, (StatusCode, String)> {
    let client = DstackClient::new();

    // Create reportData from app info (matches Phala Cloud pattern)
    let info = get_app_info();
    let info_json = serde_json::to_vec(&info)
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to serialize app info");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    // Get quote with app info embedded
    let quote = client
        .get_quote(&info_json)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get attestation quote");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    // Convert hex quote to base64 (dstack returns hex, but standard format is base64)
    let quote_bytes = hex::decode(&quote.quote)
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to decode hex quote");
            (StatusCode::INTERNAL_SERVER_ERROR, "Invalid hex quote".to_string())
        })?;
    let quote_b64 = base64::engine::general_purpose::STANDARD.encode(&quote_bytes);

    Ok(Json(AttestationResponse {
        quote: quote_b64,
        event_log: quote.event_log,
        vm_config: quote.vm_config,
    }))
}

/// GET /info
///
/// Returns application configuration that can be verified against /attestation.
/// The hash of this response is embedded in the attestation quote's reportData.
pub async fn info() -> impl IntoResponse {
    Json(get_app_info())
}

fn get_app_info() -> InfoResponse {
    InfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        name: env!("CARGO_PKG_NAME").to_string(),
        build_info: option_env!("BUILD_TIMESTAMP").map(String::from),
    }
}

/// Request body for /verify endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// Attestation data (quote, event log, vm config)
    pub attestation: DstackAttestation,
    /// Application info to verify against quote
    pub info: DstackInfo,
}

/// POST /verify
///
/// Verifies a TDX attestation quote and returns detailed verification results.
///
/// NOTE: Currently uses embedded dstack-verifier implementation instead of the official
/// dstack-verifier library from https://github.com/Dstack-TEE/dstack because:
///
/// 1. v0.5.5 is binary-only (HTTP server, not a library)
/// 2. v0.5.5 has compilation errors in ra-tls dependency (KeyRejected doesn't implement Error trait)
/// 3. Latest main branch (as of 2026-01-25) has compilation errors in tdx-attest dependency
///
/// TODO: Revisit integration with official dstack-verifier once upstream build issues are resolved.
///       Check: https://github.com/Dstack-TEE/dstack/releases
///
/// Current implementation provides:
/// - TDX quote cryptographic verification via dcap-qvl (same as official verifier)
/// - TCB status validation
/// - Report data binding to application info
/// - RTMR event log replay verification
///
/// Missing from official verifier:
/// - OS image hash verification (requires dstack-mr/ra-tls which don't compile)
pub async fn verify(
    Json(request): Json<VerifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Create verifier with default configuration
    let verifier = AttestationVerifier::new();

    // Perform verification
    let result = verifier
        .verify_attestation(&request.attestation, &request.info)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Verification failed");
            (StatusCode::BAD_REQUEST, format!("Verification failed: {}", e))
        })?;

    Ok(Json(result))
}
