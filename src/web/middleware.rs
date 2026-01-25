use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};

use crate::attestation::DstackClient;

pub async fn attestation_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    // Check if attestation is requested via query parameter
    let should_attest = request
        .uri()
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(key, _)| key == "attest")
                .map(|(_, value)| value == "true" || value == "1")
        })
        .unwrap_or(false);

    if !should_attest {
        return Ok(next.run(request).await);
    }

    // Execute the request
    let response = next.run(request).await;

    // Only process successful JSON responses
    if response.status() != StatusCode::OK {
        return Ok(response);
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("application/json") {
        return Ok(response);
    }

    // Extract the response body
    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to collect response body");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .to_bytes();

    // Get attestation quote for the response body
    let client = DstackClient::new();
    let quote = client
        .get_quote(&bytes)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get attestation quote");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Parse original response as JSON
    let original_json: Value = serde_json::from_slice(&bytes)
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to parse response as JSON");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Convert hex quote to base64 (dstack returns hex, but standard format is base64)
    let quote_bytes = hex::decode(&quote.quote)
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to decode hex quote");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let quote_b64 = base64::engine::general_purpose::STANDARD.encode(&quote_bytes);

    // Wrap with attestation
    let attested_response = json!({
        "data": original_json,
        "attestation": {
            "quote": quote_b64,
            "eventLog": quote.event_log
        }
    });

    let new_body = serde_json::to_vec(&attested_response)
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to serialize attested response");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Response::from_parts(parts, Body::from(new_body)))
}
