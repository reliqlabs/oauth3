use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::app::AppState;

pub async fn get_prove_status(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    match state.accounts.get_prove_job(&job_id).await {
        Ok(Some(job)) => match job.status.as_str() {
            "completed" => {
                let proof: serde_json::Value = job
                    .proof_json
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(json!(null));
                let data: serde_json::Value =
                    serde_json::from_slice(&job.response_body).unwrap_or(json!(null));
                (
                    StatusCode::OK,
                    Json(json!({
                        "job_id": job.id,
                        "status": "completed",
                        "prover_type": job.prover_type,
                        "data": data,
                        "proof": proof,
                    })),
                )
                    .into_response()
            }
            "failed" => (
                StatusCode::OK,
                Json(json!({
                    "job_id": job.id,
                    "status": "failed",
                    "prover_type": job.prover_type,
                    "error": job.error_message,
                })),
            )
                .into_response(),
            status => (
                StatusCode::OK,
                Json(json!({
                    "job_id": job.id,
                    "status": status,
                    "prover_type": job.prover_type,
                })),
            )
                .into_response(),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "job not found" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = ?e, "failed to get prove job");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
