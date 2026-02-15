use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::AppState;
use crate::attestation::DstackClient;
use crate::web::session::SessionUser;

#[derive(Deserialize)]
pub struct VerifyRequest {
    address: String,
    suspect: String,
}

/// Fields are alphabetically ordered for deterministic serde serialization.
/// The contract parses this same struct and verifies address == tx sender.
#[derive(Serialize)]
struct CanonicalResult {
    address: String,
    clean: bool,
    email: String,
    message_count: u64,
    suspect: String,
    timestamp: u64,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    email: String,
}

#[derive(Deserialize)]
struct GmailListResponse {
    #[serde(rename = "resultSizeEstimate", default)]
    result_size_estimate: u64,
}

/// POST /verify/gmail
///
/// Checks if the authenticated user's Gmail has received messages from the suspect email.
/// Returns a TDX-attested result proving the check was performed inside a TEE.
pub async fn verify_gmail(
    State(state): State<AppState>,
    SessionUser { user_id, .. }: SessionUser,
    Json(req): Json<VerifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Get the user's Google identity with access token
    let identity = state
        .accounts
        .get_user_identity(&user_id, "google")
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get Google identity");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to get Google identity"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "No Google account linked"})),
            )
        })?;

    let access_token = identity.access_token.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "No Google access token available"})),
        )
    })?;

    let http = reqwest::Client::new();

    // Get the user's email from Google
    let userinfo: GoogleUserInfo = http
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to call Google userinfo");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "Failed to call Google userinfo API"})),
            )
        })?
        .json()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to parse Google userinfo response");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "Failed to parse Google userinfo response"})),
            )
        })?;

    // Search Gmail for messages from the suspect
    let gmail_url = format!(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=from:{}&maxResults=1",
        urlencoding::encode(&req.suspect)
    );
    let gmail_resp: GmailListResponse = http
        .get(&gmail_url)
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to call Gmail API");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "Failed to call Gmail API"})),
            )
        })?
        .json()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to parse Gmail response");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "Failed to parse Gmail response"})),
            )
        })?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Validate suspect is a plausible email (prevent Gmail search operator injection)
    if !req.suspect.contains('@') || req.suspect.len() > 254 || req.suspect.contains('{') || req.suspect.contains('}') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid suspect email address"})),
        ));
    }

    let result = CanonicalResult {
        address: req.address,
        clean: gmail_resp.result_size_estimate == 0,
        email: userinfo.email,
        message_count: gmail_resp.result_size_estimate,
        suspect: req.suspect,
        timestamp,
    };

    let result_json = serde_json::to_string(&result).map_err(|e| {
        tracing::error!(error = ?e, "Failed to serialize result");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Serialization error"})),
        )
    })?;

    // Get TDX attestation quote over the result
    let client = DstackClient::new();
    let quote = client.get_quote(result_json.as_bytes()).await.map_err(|e| {
        tracing::error!(error = ?e, "Failed to get TDX quote");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to get TDX attestation quote"})),
        )
    })?;

    // Convert hex quote to base64
    let hex_str = quote.quote.strip_prefix("0x").unwrap_or(&quote.quote);
    let quote_bytes = hex::decode(hex_str).map_err(|e| {
        tracing::error!(error = ?e, "Failed to decode hex quote");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Invalid hex quote"})),
        )
    })?;
    let quote_b64 = base64::engine::general_purpose::STANDARD.encode(&quote_bytes);

    Ok(Json(json!({
        "result": result_json,
        "quote": quote_b64,
    })))
}

/// GET /attestation-key
///
/// Returns the TDX attestation public key extracted from a quote.
/// This key can be used to verify that future quotes come from the same TEE instance.
pub async fn attestation_key() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let client = DstackClient::new();
    let quote = client
        .get_quote(b"attestation-key-request")
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get TDX quote for attestation key");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to get TDX attestation quote"})),
            )
        })?;

    let hex_str = quote.quote.strip_prefix("0x").unwrap_or(&quote.quote);
    let quote_bytes = hex::decode(hex_str).map_err(|e| {
        tracing::error!(error = ?e, "Failed to decode hex quote");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Invalid hex quote"})),
        )
    })?;

    // Extract attestation key from TDX quote at offset 0x2BC (700), 64 bytes
    const AK_OFFSET: usize = 0x2BC;
    const AK_LEN: usize = 64;
    if quote_bytes.len() < AK_OFFSET + AK_LEN {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Quote too short to extract attestation key"})),
        ));
    }

    let ak_bytes = &quote_bytes[AK_OFFSET..AK_OFFSET + AK_LEN];
    let ak_hex = hex::encode(ak_bytes);

    Ok(Json(json!({
        "attestation_key": ak_hex,
    })))
}
