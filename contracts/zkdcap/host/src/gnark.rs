use anyhow::{bail, Context, Result};
use serde_json::json;
use std::path::Path;

use crate::ProofOutput;

/// Generate a Groth16 proof using the gnark Go binary as a subprocess.
pub async fn generate_proof(
    quote: &[u8],
    pre_verified: &dcap_qvl::verify::PreVerifiedInputs,
    now_secs: u64,
    binary_path: &str,
    pk_path: &str,
) -> Result<ProofOutput> {
    // Verify binary and pk exist
    if !Path::new(binary_path).exists() {
        bail!("gnark prove binary not found: {binary_path}");
    }
    if !Path::new(pk_path).exists() {
        bail!("gnark proving key not found: {pk_path}");
    }

    let tmp_dir = tempfile::tempdir().context("failed to create temp dir")?;
    let quote_path = tmp_dir.path().join("quote.bin");
    let pre_path = tmp_dir.path().join("pre_verified.json");
    let out_path = tmp_dir.path().join("proof.json");

    // Write quote binary
    tokio::fs::write(&quote_path, quote)
        .await
        .context("failed to write quote.bin")?;

    // Build Go-compatible PreVerifiedJSON (hex-encoded byte fields)
    let pre_json = build_pre_verified_json(pre_verified)?;
    let pre_bytes = serde_json::to_vec_pretty(&pre_json).context("failed to serialize pre_verified")?;
    tokio::fs::write(&pre_path, &pre_bytes)
        .await
        .context("failed to write pre_verified.json")?;

    // Run gnark prove binary
    tracing::info!(binary = %binary_path, "running gnark prove subprocess...");
    let output = tokio::process::Command::new(binary_path)
        .arg("-quote")
        .arg(&quote_path)
        .arg("-pre")
        .arg(&pre_path)
        .arg("-timestamp")
        .arg(now_secs.to_string())
        .arg("-pk")
        .arg(pk_path)
        .arg("-out")
        .arg(&out_path)
        .output()
        .await
        .context("failed to spawn gnark prove process")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "gnark prove failed (exit {}): stderr={}, stdout={}",
            output.status,
            stderr.trim(),
            stdout.trim()
        );
    }

    // Parse output proof JSON
    let proof_bytes = tokio::fs::read(&out_path)
        .await
        .context("failed to read proof.json output")?;
    let proof_value: serde_json::Value =
        serde_json::from_slice(&proof_bytes).context("failed to parse proof.json")?;

    // gnark outputs public_inputs as a nested object within the proof JSON;
    // it's accessed directly from proof_value["public_inputs"] by the worker
    let public_inputs = Vec::new();

    Ok(ProofOutput {
        proof: proof_value,
        public_inputs,
        journal: String::new(), // gnark doesn't produce an SP1-style journal
        zkvm: "gnark".to_string(),
    })
}

/// Build the Go-compatible `PreVerifiedJSON` format from Rust `PreVerifiedInputs`.
///
/// The Go side expects hex strings for all byte fields, matching the `PreVerifiedJSON`
/// struct in `circuits/dcap-gnark/witness/types.go`.
fn build_pre_verified_json(
    pv: &dcap_qvl::verify::PreVerifiedInputs,
) -> Result<serde_json::Value> {
    // TcbInfo serializes directly — both Rust and Go use camelCase serde
    let tcb_info = serde_json::to_value(&pv.tcb_info).context("failed to serialize tcb_info")?;

    // QeIdentity needs manual conversion: byte fields → hex strings
    let qe_identity = build_qe_identity_json(&pv.qe_identity)?;

    Ok(json!({
        "tcb_info": tcb_info,
        "qe_identity": qe_identity,
        "pck_leaf_der": hex::encode(&pv.pck_leaf_der),
        "cpu_svn": hex::encode(pv.cpu_svn),
        "pce_svn": pv.pce_svn,
        "fmspc": hex::encode(pv.fmspc),
        "ppid": hex::encode(&pv.ppid),
    }))
}

/// Convert Rust `QeIdentity` to Go `QeIdentityJSON` format (hex strings for byte fields).
fn build_qe_identity_json(
    qe: &dcap_qvl::qe_identity::QeIdentity,
) -> Result<serde_json::Value> {
    // Serialize tcb_levels directly — both sides use the same JSON shape
    let tcb_levels = serde_json::to_value(&qe.tcb_levels).context("failed to serialize qe tcb_levels")?;

    Ok(json!({
        "id": qe.id,
        "version": qe.version,
        "issueDate": qe.issue_date,
        "nextUpdate": qe.next_update,
        "tcbEvaluationDataNumber": qe.tcb_evaluation_data_number,
        "miscselect": hex::encode(qe.miscselect),
        "miscselectMask": hex::encode(qe.miscselect_mask),
        "attributes": hex::encode(qe.attributes),
        "attributesMask": hex::encode(qe.attributes_mask),
        "mrsigner": hex::encode(qe.mrsigner),
        "isvprodid": qe.isvprodid,
        "tcbLevels": tcb_levels,
    }))
}
