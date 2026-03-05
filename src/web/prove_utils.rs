use serde_json::{json, Value};
use zkdcap_host::ProofOutput;

/// Build the proof JSON object from a ProofOutput.
/// Used by both the async prove worker and the sync middleware path.
pub fn build_proof_json(proof_output: &ProofOutput) -> Value {
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
    // Pass through optional proof fields from various backends
    for key in &[
        "commitment",       // SP1 v6 Keccak commitment
        "commitment_pok",   // SP1 Keccak commitment proof of knowledge
        "commitments",      // gnark Pedersen commitment G1 points
        "public_inputs",    // gnark named public inputs (overrides empty vec above)
        "public_signals",   // gnark flat decimal-string public signals array
    ] {
        if let Some(v) = proof_output.proof.get(*key) {
            proof_value[*key] = v.clone();
        }
    }
    proof_value
}
