//! End-to-end test for dstack-attestation contract on xion-testnet-2.
//!
//! Prerequisites:
//!   - xiond binary on PATH
//!   - XION_TESTNET_MNEMONIC env var (or .env file) with funded wallet
//!   - WASM artifact at ../dstack-attestation/artifacts/dstack_attestation_contract.wasm
//!   - Network access to Intel PCS and dstack instance
//!
//! Run: cargo test --test verify_on_chain -- --nocapture

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::process::Command;
use std::time::Duration;

const RPC_URL: &str = "https://rpc.xion-testnet-2.burnt.com:443";
const CHAIN_ID: &str = "xion-testnet-2";
const KEY_NAME: &str = "dstack-test-key";
const DSTACK_APP: &str =
    "https://07f8fd641d50842c1388444af32a545416413885-8080.dstack-pha-prod5.phala.network";
const DSTACK_INFO: &str =
    "https://07f8fd641d50842c1388444af32a545416413885-8090.dstack-pha-prod5.phala.network";

const WASM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../dstack-attestation/artifacts/dstack_attestation_contract.wasm"
);

// Expected measurements from the live instance
const MR_TD: &str = "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077";
const RTMR1: &str = "c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc";
const RTMR2: &str = "5c993ed29378b41d94a402055aee9294c5de3b6daa07542cbc734e3a4789eef5a7cd35590bac7804dcf2bcc90b77482b";
const COMPOSE_HASH: &str =
    "a813afbc448bf5794d40af9239b36c5b124ded9bcc22b063ba4cb1f0105cbf55";
const OS_IMAGE_HASH: &str =
    "ead0c34c9aabca991f94b2dc9a40a413b2fa9e04a57cf792daad045e3adbf253";

// ─── helpers ───────────────────────────────────────────────────

fn xiond(args: &[&str]) -> String {
    let out = Command::new("xiond")
        .args(args)
        .output()
        .expect("xiond not found on PATH");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !stderr.is_empty() && !out.status.success() {
        panic!("xiond {:?} failed:\nstdout: {}\nstderr: {}", args, stdout, stderr);
    }
    stdout
}

fn xiond_json(args: &[&str]) -> serde_json::Value {
    let mut full_args = args.to_vec();
    full_args.push("-o");
    full_args.push("json");
    let out = xiond(&full_args);
    serde_json::from_str(&out).unwrap_or_else(|e| {
        panic!("Failed to parse xiond JSON output: {}\nRaw: {}", e, &out[..out.len().min(500)]);
    })
}

fn wait_for_tx(txhash: &str) -> serde_json::Value {
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(2));
        let result = Command::new("xiond")
            .args([
                "q", "tx", txhash,
                "--node", RPC_URL,
                "-o", "json",
            ])
            .output()
            .expect("xiond not found");
        if result.status.success() {
            let val: serde_json::Value =
                serde_json::from_slice(&result.stdout).expect("parse tx json");
            return val;
        }
    }
    panic!("TX {} not found after 60s", txhash);
}

fn extract_attr(tx: &serde_json::Value, event_type: &str, key: &str) -> Option<String> {
    tx["events"]
        .as_array()?
        .iter()
        .filter(|e| e["type"].as_str() == Some(event_type))
        .flat_map(|e| e["attributes"].as_array())
        .flatten()
        .find(|a| a["key"].as_str() == Some(key))
        .and_then(|a| a["value"].as_str().map(String::from))
}

// ─── data fetching ─────────────────────────────────────────────

#[derive(Deserialize)]
struct AttestationResponse {
    quote: String, // base64
}

async fn fetch_quote(client: &reqwest::Client) -> (Vec<u8>, String) {
    let resp: AttestationResponse = client
        .get(format!("{}/attestation", DSTACK_APP))
        .send()
        .await
        .expect("fetch quote")
        .json()
        .await
        .expect("parse attestation json");
    let quote_bytes = B64.decode(&resp.quote).expect("decode quote base64");
    (quote_bytes, resp.quote)
}

#[derive(Deserialize)]
struct RawEventLogEntry {
    imr: u32,
    #[allow(dead_code)]
    event_type: u64,
    event: String,
    event_payload: String, // hex
}

async fn fetch_event_log(client: &reqwest::Client) -> Vec<RawEventLogEntry> {
    let html = client
        .get(DSTACK_INFO)
        .send()
        .await
        .expect("fetch info page")
        .text()
        .await
        .expect("read info html");

    // Unescape HTML entities first
    let unescaped = html
        .replace("&#34;", "\"")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");

    // Find the event_log JSON array
    let re = Regex::new(r#"(?s)"event_log"\s*:\s*(\[.*?\])\s*[,}]"#).unwrap();
    let json_str = re
        .captures(&unescaped)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .expect("find event_log JSON in HTML");

    let all_events: Vec<RawEventLogEntry> =
        serde_json::from_str(&json_str).expect("parse event log json");

    // Filter to RTMR3 events (imr == 3)
    all_events.into_iter().filter(|e| e.imr == 3).collect()
}

async fn fetch_collateral(quote_bytes: &[u8]) -> Vec<u8> {
    let collateral = dcap_qvl::collateral::get_collateral_from_pcs(quote_bytes)
        .await
        .expect("fetch collateral from Intel PCS");
    serde_json::to_vec(&collateral).expect("serialize collateral")
}

// ─── contract msg types ────────────────────────────────────────

#[derive(Serialize)]
struct InstantiateMsg {
    expected_measurements: Option<ExpectedMeasurementsMsg>,
    expected_events: Option<ExpectedEventsMsg>,
}

#[derive(Serialize)]
struct ExpectedMeasurementsMsg {
    mr_td: String,
    rtmr1: String,
    rtmr2: String,
    rtmr0: Option<String>,
    check_rtmr0: bool,
}

#[derive(Serialize)]
struct ExpectedEventsMsg {
    compose_hash: Option<String>,
    os_image_hash: Option<String>,
}

#[derive(Serialize)]
struct EventLogEntry {
    event: String,
    payload: String, // base64
}

#[derive(Serialize)]
struct VerifyAttestationMsg {
    verify_attestation: VerifyAttestationInner,
}

#[derive(Serialize)]
struct VerifyAttestationInner {
    quote: String,      // base64
    collateral: String, // base64
    event_log: Vec<EventLogEntry>,
}

#[derive(Serialize)]
struct QueryVerification {
    get_verification: GetVerificationInner,
}

#[derive(Serialize)]
struct GetVerificationInner {
    quote_hash: String,
}

// ─── test ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_verify_attestation_on_chain() {
    // Load .env (check local first, then root)
    dotenvy::from_filename(format!("{}/.env", env!("CARGO_MANIFEST_DIR"))).ok();
    dotenvy::from_filename(format!("{}/../../.env", env!("CARGO_MANIFEST_DIR"))).ok();

    let mnemonic = std::env::var("XION_TESTNET_MNEMONIC")
        .expect("Set XION_TESTNET_MNEMONIC in .env or environment");

    // ── 1. Import mnemonic into xiond keyring ──
    eprintln!("=== Importing wallet ===");

    // Try to import the key. Pipe mnemonic to stdin.
    use std::io::Write as _;
    let mut child = Command::new("xiond")
        .args([
            "keys", "add", KEY_NAME,
            "--keyring-backend", "test",
            "--recover",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn xiond keys add");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(mnemonic.trim().as_bytes())
        .expect("write mnemonic");
    let import_out = child.wait_with_output().expect("wait keys add");
    let import_stderr = String::from_utf8_lossy(&import_out.stderr).to_string();

    // Determine key name to use
    let key_name = if import_out.status.success() {
        KEY_NAME.to_string()
    } else if import_stderr.contains("duplicated address") || import_stderr.contains("already exists") {
        // Mnemonic already imported under a different name — find it
        let list_out = Command::new("xiond")
            .args(["keys", "list", "--keyring-backend", "test", "--output", "json"])
            .output()
            .expect("xiond keys list");
        let keys: Vec<serde_json::Value> =
            serde_json::from_slice(&list_out.stdout).unwrap_or_default();

        // Derive the address via dry-run
        let mut dry = Command::new("xiond")
            .args([
                "keys", "add", "tmp-dry",
                "--keyring-backend", "test",
                "--recover",
                "--dry-run",
                "--output", "json",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn dry-run");
        dry.stdin.take().unwrap().write_all(mnemonic.trim().as_bytes()).unwrap();
        let dry_out = dry.wait_with_output().expect("dry-run");
        let dry_stdout = String::from_utf8_lossy(&dry_out.stdout);
        let dry_json: serde_json::Value = serde_json::from_str(dry_stdout.trim())
            .unwrap_or_else(|e| {
                // Might be in stderr
                let dry_stderr = String::from_utf8_lossy(&dry_out.stderr);
                panic!("parse dry-run: {}\nstdout: {}\nstderr: {}", e, dry_stdout, dry_stderr);
            });
        let target_addr = dry_json["address"].as_str().unwrap();

        keys.iter()
            .find_map(|k| {
                if k["address"].as_str() == Some(target_addr) {
                    k["name"].as_str().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("Could not find existing key for address {}", target_addr))
    } else {
        panic!("Failed to import key: {}", import_stderr);
    };

    eprintln!("Using key: {}", key_name);
    let address = {
        let out = Command::new("xiond")
            .args(["keys", "show", &key_name, "--keyring-backend", "test", "-a"])
            .output()
            .expect("keys show");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    eprintln!("Wallet address: {}", address);

    // Check balance
    let balance_out = xiond(&[
        "q", "bank", "balances", &address,
        "--node", RPC_URL,
    ]);
    eprintln!("Balance: {}", balance_out.trim());

    // ── 2. Fetch attestation data ──
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    eprintln!("=== Fetching quote from dstack instance ===");
    let (quote_bytes, quote_b64) = fetch_quote(&client).await;
    eprintln!("Quote: {} bytes", quote_bytes.len());

    eprintln!("=== Fetching event log from dstack info page ===");
    let raw_events = fetch_event_log(&client).await;
    eprintln!("RTMR3 events: {}", raw_events.len());
    for e in &raw_events {
        eprintln!("  {}", e.event);
    }

    eprintln!("=== Fetching collateral from Intel PCS ===");
    let collateral_bytes = fetch_collateral(&quote_bytes).await;
    eprintln!("Collateral: {} bytes", collateral_bytes.len());

    // ── 3. Prepare event log for contract ──
    let event_log: Vec<EventLogEntry> = raw_events
        .iter()
        .map(|e| {
            let payload_bytes = hex::decode(&e.event_payload).unwrap_or_default();
            EventLogEntry {
                event: e.event.clone(),
                payload: B64.encode(&payload_bytes),
            }
        })
        .collect();

    // ── 4. Store WASM ──
    eprintln!("=== Storing WASM on chain ===");
    assert!(
        std::path::Path::new(WASM_PATH).exists(),
        "WASM not found at {}. Run the docker optimizer first.",
        WASM_PATH
    );

    let store_out = xiond(&[
        "tx", "wasm", "store", WASM_PATH,
        "--from", &key_name,
        "--keyring-backend", "test",
        "--node", RPC_URL,
        "--chain-id", CHAIN_ID,
        "--gas", "20000000",
        "--fees", "500000uxion",
        "-y",
        "--output", "json",
    ]);
    let store_tx: serde_json::Value =
        serde_json::from_str(&store_out).expect("parse store tx output");
    let txhash = store_tx["txhash"]
        .as_str()
        .expect("store txhash");
    eprintln!("Store TX: {}", txhash);

    let store_result = wait_for_tx(txhash);
    let code = store_result["code"].as_u64().unwrap_or(999);
    assert_eq!(code, 0, "Store TX failed: {}", store_result["raw_log"]);

    let code_id = extract_attr(&store_result, "store_code", "code_id")
        .expect("extract code_id from store tx");
    eprintln!("Code ID: {}", code_id);

    // ── 5. Instantiate contract ──
    eprintln!("=== Instantiating contract ===");
    let init_msg = InstantiateMsg {
        expected_measurements: Some(ExpectedMeasurementsMsg {
            mr_td: MR_TD.to_string(),
            rtmr1: RTMR1.to_string(),
            rtmr2: RTMR2.to_string(),
            rtmr0: None,
            check_rtmr0: false,
        }),
        expected_events: Some(ExpectedEventsMsg {
            compose_hash: Some(COMPOSE_HASH.to_string()),
            os_image_hash: Some(OS_IMAGE_HASH.to_string()),
        }),
    };
    let init_json = serde_json::to_string(&init_msg).unwrap();

    let label = format!("dstack-attestation-e2e-{}", chrono_timestamp());

    let inst_out = xiond(&[
        "tx", "wasm", "instantiate", &code_id, &init_json,
        "--label", &label,
        "--from", &key_name,
        "--admin", &address,
        "--keyring-backend", "test",
        "--node", RPC_URL,
        "--chain-id", CHAIN_ID,
        "--gas", "500000",
        "--fees", "50000uxion",
        "-y",
        "--output", "json",
    ]);
    let inst_tx: serde_json::Value =
        serde_json::from_str(&inst_out).expect("parse instantiate tx output");
    let txhash = inst_tx["txhash"].as_str().expect("instantiate txhash");
    eprintln!("Instantiate TX: {}", txhash);

    let inst_result = wait_for_tx(txhash);
    let code = inst_result["code"].as_u64().unwrap_or(999);
    assert_eq!(code, 0, "Instantiate TX failed: {}", inst_result["raw_log"]);

    let contract_addr = extract_attr(&inst_result, "instantiate", "_contract_address")
        .expect("extract contract address");
    eprintln!("Contract: {}", contract_addr);

    // Verify config was stored
    let config = xiond_json(&[
        "q", "wasm", "contract-state", "smart", &contract_addr,
        r#"{"get_config":{}}"#,
        "--node", RPC_URL,
    ]);
    eprintln!("Config: {}", config["data"]);

    // ── 6. Execute verify_attestation ──
    eprintln!("=== Submitting verification TX ===");
    let collateral_b64 = B64.encode(&collateral_bytes);

    let verify_msg = VerifyAttestationMsg {
        verify_attestation: VerifyAttestationInner {
            quote: quote_b64.clone(),
            collateral: collateral_b64,
            event_log,
        },
    };
    let verify_json = serde_json::to_string(&verify_msg).unwrap();

    let exec_out = xiond(&[
        "tx", "wasm", "execute", &contract_addr, &verify_json,
        "--from", &key_name,
        "--keyring-backend", "test",
        "--node", RPC_URL,
        "--chain-id", CHAIN_ID,
        "--gas", "50000000",
        "--fees", "500000uxion",
        "-y",
        "--output", "json",
    ]);
    let exec_tx: serde_json::Value =
        serde_json::from_str(&exec_out).expect("parse execute tx output");
    let txhash = exec_tx["txhash"].as_str().expect("execute txhash");
    eprintln!("Verify TX: {}", txhash);

    let exec_result = wait_for_tx(txhash);
    let code = exec_result["code"].as_u64().unwrap_or(999);

    // Print wasm events
    if let Some(events) = exec_result["events"].as_array() {
        for evt in events {
            if evt["type"].as_str() == Some("wasm") {
                eprintln!("\nWASM events:");
                if let Some(attrs) = evt["attributes"].as_array() {
                    for attr in attrs {
                        eprintln!(
                            "  {}: {}",
                            attr["key"].as_str().unwrap_or("?"),
                            attr["value"].as_str().unwrap_or("?")
                        );
                    }
                }
            }
        }
    }

    if code != 0 {
        let raw_log = exec_result["raw_log"]
            .as_str()
            .unwrap_or("no raw_log");
        eprintln!("\nVerification TX failed (code {}): {}", code, raw_log);
        // Don't assert yet — print diagnostics first
    }

    assert_eq!(code, 0, "Verify TX failed");

    // ── 7. Query verification record ──
    eprintln!("\n=== Querying verification record ===");
    let quote_hash = hex::encode(Sha256::digest(&quote_bytes));
    let query_msg = QueryVerification {
        get_verification: GetVerificationInner {
            quote_hash: quote_hash.clone(),
        },
    };
    let query_json = serde_json::to_string(&query_msg).unwrap();

    let record = xiond_json(&[
        "q", "wasm", "contract-state", "smart", &contract_addr,
        &query_json,
        "--node", RPC_URL,
    ]);
    let data = &record["data"];
    eprintln!("Verification record:");
    eprintln!("  quote_verified: {}", data["quote_verified"]);
    eprintln!("  rtmr3_verified: {}", data["rtmr3_verified"]);
    eprintln!("  measurements_verified: {}", data["measurements_verified"]);
    eprintln!("  events_verified: {}", data["events_verified"]);
    eprintln!("  all_passed: {}", data["all_passed"]);
    eprintln!("  tcb_status: {}", data["tcb_status"]);
    if let Some(mismatches) = data["mismatches"].as_array() {
        if !mismatches.is_empty() {
            eprintln!("  mismatches:");
            for m in mismatches {
                eprintln!("    - {}", m.as_str().unwrap_or("?"));
            }
        }
    }

    // Assert key fields
    assert_eq!(data["quote_verified"], true, "quote should be verified");
    assert_eq!(data["rtmr3_verified"], true, "rtmr3 should match");
    assert_eq!(data["measurements_verified"], true, "measurements should match");
    assert_eq!(data["events_verified"], true, "events should match");
    assert_eq!(data["all_passed"], true, "all checks should pass");

    eprintln!("\n=== ALL CHECKS PASSED ===");
    eprintln!("Contract: {}", contract_addr);
    eprintln!("Quote hash: {}", quote_hash);
}

fn chrono_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
