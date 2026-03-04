use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures::FutureExt;
use crate::app::AppState;
use crate::attestation::DstackClient;
use crate::models::prove_job::{ProveJob, ProverType};
use crate::web::prove_utils::build_proof_json;

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
                    let job_id = job.id.clone();
                    tracing::info!(job_id = %job_id, prover_type = %job.prover_type, "processing prove job");

                    // Catch panics so the worker loop survives
                    let result =
                        AssertUnwindSafe(process_job(&state, job)).catch_unwind().await;

                    if let Err(e) = result {
                        let msg = if let Some(s) = e.downcast_ref::<String>() {
                            s.clone()
                        } else if let Some(s) = e.downcast_ref::<&str>() {
                            s.to_string()
                        } else {
                            "unknown panic".to_string()
                        };
                        tracing::error!(job_id = %job_id, error = %msg, "prove job panicked!");
                        // Mark job as failed so it doesn't stay stuck
                        let now = time::OffsetDateTime::now_utc().to_string();
                        let fail_job = ProveJob {
                            id: job_id,
                            status: "failed".to_string(),
                            error_message: Some(format!("worker panic: {msg}")),
                            updated_at: now,
                            request_uri: String::new(),
                            response_body: Vec::new(),
                            quote_hex: None,
                            proof_json: None,
                            created_at: String::new(),
                            prover_type: String::new(),
                        };
                        let _ = state.accounts.update_prove_job(&fail_job).await;
                    }
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
    tracing::info!(job_id = %job.id, "fetching TDX attestation quote...");
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

    tracing::info!(job_id = %job.id, quote_len = quote_bytes.len(), "TDX quote obtained");
    job.quote_hex = Some(quote.quote.clone());
    job.updated_at = now();
    let _ = state.accounts.update_prove_job(&job).await;

    // Step 2: Resolve prover backend from job.prover_type
    let backend = match ProverType::from_db(&job.prover_type) {
        Some(ProverType::GnarkGpu) => {
            let socket = std::env::var("GNARK_GPU_SOCKET")
                .unwrap_or_else(|_| "/tmp/gnark-prove-gpu.sock".into());
            zkdcap_host::ProverBackend::Gnark { socket_path: socket, gpu: true }
        }
        Some(ProverType::GnarkCpu) => {
            let socket = std::env::var("GNARK_CPU_SOCKET")
                .unwrap_or_else(|_| "/tmp/gnark-prove-cpu.sock".into());
            zkdcap_host::ProverBackend::Gnark { socket_path: socket, gpu: false }
        }
        _ => zkdcap_host::ProverBackend::Sp1,
    };

    // Step 3: Generate ZK proof
    tracing::info!(job_id = %job.id, prover_type = %job.prover_type, "starting prove pipeline...");
    match zkdcap_host::prove_quote(&quote_bytes, &backend).await {
        Ok(proof_output) => {
            let proof_value = build_proof_json(&proof_output);
            job.status = "completed".to_string();
            job.proof_json = Some(proof_value.to_string());
            job.updated_at = now();
            tracing::info!(job_id = %job.id, "prove job completed");
        }
        Err(e) => {
            tracing::error!(job_id = %job.id, error = ?e, "prove pipeline failed");
            job.status = "failed".to_string();
            job.error_message = Some(format!("proof generation failed: {e}"));
            job.updated_at = now();
        }
    }

    if let Err(e) = state.accounts.update_prove_job(&job).await {
        tracing::error!(job_id = %job.id, error = ?e, "failed to update prove job");
    }
}
