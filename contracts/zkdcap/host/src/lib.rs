use anyhow::{Context, Result};
use serde::Serialize;

pub mod sp1;

/// Output proof format (SnarkJS-compatible)
#[derive(Serialize)]
pub struct ProofOutput {
    pub proof: serde_json::Value,
    pub public_inputs: Vec<String>,
    pub journal: String, // hex-encoded DcapJournal bytes
    pub zkvm: String,
}

/// Generate a Groth16 ZK proof for a raw TDX quote.
///
/// This is the full pipeline:
/// 1. Fetch collateral from Intel PCS
/// 2. Extract pre-verified inputs (cert chain validation on host)
/// 3. Generate SP1 Groth16 proof (lite guest — steps 4-10 in zkVM)
pub async fn prove_quote(quote: &[u8]) -> Result<ProofOutput> {
    let collateral = dcap_qvl::collateral::get_collateral_from_pcs(quote)
        .await
        .context("failed to fetch collateral from Intel PCS")?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let pre_verified =
        dcap_qvl::verify::rustcrypto::extract_pre_verified(quote, &collateral, now_secs)
            .context("failed to extract pre-verified inputs")?;

    sp1::generate_proof(quote, &pre_verified, now_secs).await
}
