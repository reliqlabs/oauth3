use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};

use crate::app::AppState;
use crate::attestation::DstackClient;
use crate::models::prove_job::{ProveJob, ProverType};

pub async fn prove_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let prover_type = request
        .uri()
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(key, _)| key == "prove")
                .and_then(|(_, value)| ProverType::from_query_value(&value))
        });

    let prover_type = match prover_type {
        Some(pt) => pt,
        None => return Ok(next.run(request).await),
    };

    let request_uri = request.uri().to_string();
    let response = next.run(request).await;

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

    let (_, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "failed to collect response body");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .to_bytes();

    let job_id = uuid::Uuid::new_v4().to_string();
    let now = time::OffsetDateTime::now_utc().to_string();

    let job = ProveJob {
        id: job_id.clone(),
        status: "pending".to_string(),
        request_uri,
        response_body: bytes.to_vec(),
        quote_hex: None,
        proof_json: None,
        error_message: None,
        created_at: now.clone(),
        updated_at: now,
        prover_type: prover_type.as_str().to_string(),
    };

    state.accounts.create_prove_job(job).await.map_err(|e| {
        tracing::error!(error = ?e, "failed to create prove job");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let resp = json!({
        "job_id": job_id,
        "status": "pending",
        "prover_type": prover_type.as_str(),
        "poll_url": format!("/prove/{}", job_id),
    });

    let body = serde_json::to_vec(&resp).map_err(|e| {
        tracing::error!(error = ?e, "failed to serialize prove job response");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap())
}

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
