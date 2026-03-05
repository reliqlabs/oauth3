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
use crate::web::prove_utils::build_proof_json;

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

    // Sync proving path — block and return inline response
    if prover_type.is_sync() {
        return prove_sync(prover_type, &bytes).await;
    }

    // Async job queue path
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

/// Synchronous prove path: get TDX quote, generate proof, return inline.
async fn prove_sync(
    prover_type: ProverType,
    response_body: &[u8],
) -> Result<Response, StatusCode> {
    tracing::info!(prover_type = prover_type.as_str(), "sync prove: fetching TDX quote...");

    let client = DstackClient::new();
    let quote = client.get_quote(response_body).await.map_err(|e| {
        tracing::error!(error = ?e, "sync prove: failed to get attestation quote");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let quote_bytes = hex::decode(&quote.quote).map_err(|e| {
        tracing::error!(error = ?e, "sync prove: failed to decode hex quote");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!(quote_len = quote_bytes.len(), "sync prove: TDX quote obtained, starting proof...");

    let backend = match prover_type {
        ProverType::GnarkGpuSync => {
            let socket = std::env::var("GNARK_GPU_SOCKET")
                .unwrap_or_else(|_| "/tmp/gnark-prove-gpu.sock".into());
            zkdcap_host::ProverBackend::Gnark { socket_path: socket, gpu: true }
        }
        // Fallback (shouldn't reach here due to is_sync() gate)
        _ => unreachable!("prove_sync called with non-sync prover type"),
    };

    let proof_output = zkdcap_host::prove_quote(&quote_bytes, &backend).await.map_err(|e| {
        tracing::error!(error = ?e, "sync prove: proof generation failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!(prover_type = prover_type.as_str(), "sync prove: completed");

    let original_json: Value = serde_json::from_slice(response_body).map_err(|e| {
        tracing::error!(error = ?e, "sync prove: failed to parse response body as JSON");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let proof_value = build_proof_json(&proof_output);

    let resp = json!({
        "data": original_json,
        "proof": proof_value,
        "prover_type": prover_type.as_str(),
    });

    let body = serde_json::to_vec(&resp).map_err(|e| {
        tracing::error!(error = ?e, "sync prove: failed to serialize response");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
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
