use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures::FutureExt;
use serde_json::json;

use crate::app::AppState;
use crate::attestation::DstackClient;
use crate::models::prove_job::{ProveJob, ProverType};

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
        Some(ProverType::GnarkCpu | ProverType::GnarkGpu) => {
            let binary = std::env::var("GNARK_PROVE_BINARY").unwrap_or_else(|_| "gnark-prove".into());
            let pk = std::env::var("GNARK_PK_PATH").unwrap_or_else(|_| "pk.bin".into());
            zkdcap_host::ProverBackend::Gnark { binary_path: binary, pk_path: pk }
        }
        _ => zkdcap_host::ProverBackend::Sp1,
    };

    // Step 3: Generate ZK proof
    tracing::info!(job_id = %job.id, prover_type = %job.prover_type, "starting prove pipeline...");
    match zkdcap_host::prove_quote(&quote_bytes, &backend).await {
        Ok(proof_output) => {
            // Include the full proof (pi_a/b/c + optional commitment fields)
            let mut proof_value = json!({
                "pi_a": proof_output.proof["pi_a"],
                "pi_b": proof_output.proof["pi_b"],
                "pi_c": proof_output.proof["pi_c"],
                "protocol": proof_output.proof["protocol"],
                "curve": proof_output.proof["curve"],
                "public_inputs": proof_output.public_inputs,
                "journal": proof_output.journal,
                "zkvm": proof_output.zkvm,
            });
            // SP1 v6 Keccak commitment fields (if present)
            if let Some(c) = proof_output.proof.get("commitment") {
                proof_value["commitment"] = c.clone();
            }
            if let Some(p) = proof_output.proof.get("commitment_pok") {
                proof_value["commitment_pok"] = p.clone();
            }
            // gnark public_inputs (if present — nested object from gnark witness)
            if let Some(pi) = proof_output.proof.get("public_inputs") {
                proof_value["public_inputs"] = pi.clone();
            }
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
