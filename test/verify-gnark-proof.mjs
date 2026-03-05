/**
 * Gnark Groth16 proof verification test.
 *
 * Usage:
 *   node test/verify-gnark-proof.mjs [--url <URL>] [--vkey <path>] [--proof <path>]
 *
 * Examples:
 *   # Fetch from deployed CVM and verify format
 *   node test/verify-gnark-proof.mjs --url "https://host/info?prove=gnark-gpu-sync" --vkey /tmp/gnark-vkey.json
 *
 *   # Verify a local proof file
 *   node test/verify-gnark-proof.mjs --proof proof-response.json --vkey /tmp/gnark-vkey.json
 *
 * Note: gnark v0.14 uses Pedersen commitments which modify the Groth16 verification equation.
 * Standard snarkjs.groth16.verify() will FAIL because it doesn't account for the commitment
 * point added to the pairing's kSum. Use the Go verify-remote tool for full verification.
 * This test validates proof structure and public signal integrity.
 */

import { readFileSync } from "fs";
import * as snarkjs from "snarkjs";

// Parse CLI args
const args = process.argv.slice(2);
function getArg(name) {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : null;
}

const url = getArg("url");
const vkeyPath = getArg("vkey") || "/tmp/gnark-vkey.json";
const proofPath = getArg("proof");

if (!url && !proofPath) {
  console.error(
    "Usage: node test/verify-gnark-proof.mjs --url <URL> --vkey <vkey.json>"
  );
  console.error(
    "       node test/verify-gnark-proof.mjs --proof <file.json> --vkey <vkey.json>"
  );
  process.exit(1);
}

// Load verification key
console.log(`Loading verification key from ${vkeyPath}...`);
const vkey = JSON.parse(readFileSync(vkeyPath, "utf8"));
console.log(
  `  nPublic: ${vkey.nPublic}, IC: ${vkey.IC.length}, nCommitments: ${vkey.nCommitments || 0}`
);

// Fetch or load proof
let responseJSON;
if (url) {
  console.log(`\nFetching proof from ${url}...`);
  const t0 = Date.now();
  const resp = await fetch(url);
  const elapsed = Date.now() - t0;
  console.log(
    `  Response: ${resp.status} ${resp.statusText} (${elapsed}ms)`
  );
  if (!resp.ok) {
    const body = await resp.text();
    console.error(`  Error: ${body.slice(0, 500)}`);
    process.exit(1);
  }
  responseJSON = await resp.json();
} else {
  console.log(`\nLoading proof from ${proofPath}...`);
  responseJSON = JSON.parse(readFileSync(proofPath, "utf8"));
}

// Extract proof object (handle both wrapped and direct formats)
let proof, data;
if (responseJSON.proof && responseJSON.data !== undefined) {
  // Wrapped format: { data: ..., proof: ..., prover_type: ... }
  proof = responseJSON.proof;
  data = responseJSON.data;
  console.log(`  prover_type: ${responseJSON.prover_type}`);
} else if (responseJSON.pi_a) {
  // Direct proof format
  proof = responseJSON;
} else {
  console.error("Unrecognized response format");
  process.exit(1);
}

// Validate proof structure
console.log("\n--- Proof Structure Validation ---");
let errors = 0;

function check(condition, msg) {
  if (condition) {
    console.log(`  PASS: ${msg}`);
  } else {
    console.log(`  FAIL: ${msg}`);
    errors++;
  }
}

check(proof.protocol === "groth16", `protocol = ${proof.protocol}`);
check(proof.curve === "bn128", `curve = ${proof.curve}`);
check(
  Array.isArray(proof.pi_a) && proof.pi_a.length === 3,
  `pi_a has 3 components (got ${proof.pi_a?.length})`
);
check(
  Array.isArray(proof.pi_b) && proof.pi_b.length === 3,
  `pi_b has 3 rows (got ${proof.pi_b?.length})`
);
check(
  Array.isArray(proof.pi_c) && proof.pi_c.length === 3,
  `pi_c has 3 components (got ${proof.pi_c?.length})`
);

// Check values are valid decimal strings (large numbers)
function isDecimalString(s) {
  return typeof s === "string" && /^\d+$/.test(s) && s.length > 10;
}
check(isDecimalString(proof.pi_a?.[0]), "pi_a[0] is valid decimal");
check(isDecimalString(proof.pi_c?.[0]), "pi_c[0] is valid decimal");

// Validate public inputs
const hasPublicInputs =
  proof.public_inputs && typeof proof.public_inputs === "object";
check(hasPublicInputs, "public_inputs present");
if (hasPublicInputs) {
  const fields = Object.keys(proof.public_inputs);
  console.log(`  public_inputs fields: ${fields.join(", ")}`);
}

// Validate public signals (flat array)
const hasPublicSignals =
  Array.isArray(proof.public_signals) && proof.public_signals.length > 0;
check(hasPublicSignals, `public_signals present (${proof.public_signals?.length || 0} signals)`);
if (hasPublicSignals) {
  const expectedSignals = vkey.nPublic;
  check(
    proof.public_signals.length === expectedSignals,
    `public_signals count matches vkey.nPublic (${proof.public_signals.length} == ${expectedSignals})`
  );
  check(
    isDecimalString(proof.public_signals[0]),
    "public_signals[0] is valid decimal"
  );
}

// Validate Pedersen commitment data
const nCommitments = vkey.nCommitments || 0;
if (nCommitments > 0) {
  const hasCommitments =
    Array.isArray(proof.commitments) &&
    proof.commitments.length === nCommitments;
  check(
    hasCommitments,
    `commitments present (${proof.commitments?.length || 0} == ${nCommitments})`
  );
  if (hasCommitments) {
    check(
      proof.commitments[0].length === 3,
      "commitment[0] has 3 components (G1 affine)"
    );
    check(
      isDecimalString(proof.commitments[0][0]),
      "commitment[0][0] is valid decimal"
    );
  }

  const hasPok =
    Array.isArray(proof.commitment_pok) && proof.commitment_pok.length === 3;
  check(hasPok, "commitment_pok present");
}

// Validate zkvm field
check(proof.zkvm === "gnark", `zkvm = ${proof.zkvm}`);

// Summary
console.log("\n--- Summary ---");
if (errors > 0) {
  console.log(`${errors} check(s) FAILED`);
} else {
  console.log("All structure checks PASSED");
}

// Attempt snarkjs verification (expected to fail for gnark Pedersen proofs)
if (hasPublicSignals && nCommitments > 0) {
  console.log("\n--- snarkjs.groth16.verify (informational) ---");
  console.log(
    "NOTE: gnark v0.14 Pedersen-commitment proofs are NOT verifiable by stock snarkjs."
  );
  console.log(
    "The verification equation differs: gnark adds commitment points to the pairing."
  );
  console.log("Use the Go verify-remote tool for correct full verification.\n");

  try {
    const snarkProof = {
      pi_a: proof.pi_a,
      pi_b: proof.pi_b,
      pi_c: proof.pi_c,
      protocol: proof.protocol,
      curve: proof.curve,
    };
    const result = await snarkjs.groth16.verify(
      vkey,
      proof.public_signals,
      snarkProof
    );
    if (result) {
      console.log("  snarkjs.groth16.verify: PASSED (unexpected for Pedersen proofs!)");
    } else {
      console.log(
        "  snarkjs.groth16.verify: FAILED (expected — commitment not in pairing)"
      );
    }
  } catch (e) {
    console.log(`  snarkjs.groth16.verify: ERROR — ${e.message}`);
  }
} else if (hasPublicSignals && nCommitments === 0) {
  // No commitments — standard snarkjs verification should work
  console.log("\n--- snarkjs.groth16.verify ---");
  try {
    const snarkProof = {
      pi_a: proof.pi_a,
      pi_b: proof.pi_b,
      pi_c: proof.pi_c,
      protocol: proof.protocol,
      curve: proof.curve,
    };
    const result = await snarkjs.groth16.verify(
      vkey,
      proof.public_signals,
      snarkProof
    );
    console.log(`  Result: ${result ? "PASSED" : "FAILED"}`);
    if (!result) errors++;
  } catch (e) {
    console.log(`  ERROR: ${e.message}`);
    errors++;
  }
}

process.exit(errors > 0 ? 1 : 0);
