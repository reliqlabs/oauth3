use std::time::Duration;

use serde_json::json;

use crate::app::AppState;
use crate::attestation::DstackClient;
use crate::models::prove_job::ProveJob;

pub fn spawn_prove_worker(state: AppState) {
    tokio::spawn(async move {
        // Reset any jobs stuck as 'running' from a previous crash
        match state.accounts.reset_running_prove_jobs().await {
            Ok(n) if n > 0 => tracing::info!(count = n, "reset stale running prove jobs"),
            Err(e) => tracing::error!(error = ?e, "failed to reset running prove jobs"),
            _ => {}
        }

        loop {
            match state.accounts.claim_next_prove_job().await {
                Ok(Some(job)) => {
                    tracing::info!(job_id = %job.id, "processing prove job");
                    process_job(&state, job).await;
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    tracing::error!(error = ?e, "failed to claim prove job");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });
}

async fn process_job(state: &AppState, mut job: ProveJob) {
    let now = || time::OffsetDateTime::now_utc().to_string();

    // Step 1: Get TDX quote for the response body
    let client = DstackClient::new();
    let quote = match client.get_quote(&job.response_body).await {
        Ok(q) => q,
        Err(e) => {
            tracing::error!(job_id = %job.id, error = ?e, "failed to get attestation quote");
            job.status = "failed".to_string();
            job.error_message = Some(format!("attestation quote failed: {e}"));
            job.updated_at = now();
            let _ = state.accounts.update_prove_job(&job).await;
            return;
        }
    };

    let quote_bytes = match hex::decode(&quote.quote) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(job_id = %job.id, error = ?e, "failed to decode hex quote");
            job.status = "failed".to_string();
            job.error_message = Some(format!("hex decode failed: {e}"));
            job.updated_at = now();
            let _ = state.accounts.update_prove_job(&job).await;
            return;
        }
    };

    job.quote_hex = Some(quote.quote.clone());
    job.updated_at = now();
    let _ = state.accounts.update_prove_job(&job).await;

    // Step 2: Generate ZK proof
    tracing::info!(job_id = %job.id, quote_len = quote_bytes.len(), "generating zkDCAP proof...");
    match zkdcap_host::prove_quote(&quote_bytes).await {
        Ok(proof_output) => {
            let proof_value = json!({
                "pi_a": proof_output.proof["pi_a"],
                "pi_b": proof_output.proof["pi_b"],
                "pi_c": proof_output.proof["pi_c"],
                "protocol": proof_output.proof["protocol"],
                "curve": proof_output.proof["curve"],
                "public_inputs": proof_output.public_inputs,
                "journal": proof_output.journal,
                "zkvm": proof_output.zkvm,
            });
            job.status = "completed".to_string();
            job.proof_json = Some(proof_value.to_string());
            job.updated_at = now();
            tracing::info!(job_id = %job.id, "prove job completed");
        }
        Err(e) => {
            tracing::error!(job_id = %job.id, error = ?e, "zkDCAP proof generation failed");
            job.status = "failed".to_string();
            job.error_message = Some(format!("proof generation failed: {e}"));
            job.updated_at = now();
        }
    }

    if let Err(e) = state.accounts.update_prove_job(&job).await {
        tracing::error!(job_id = %job.id, error = ?e, "failed to update prove job");
    }
}
