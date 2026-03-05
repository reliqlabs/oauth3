# dstack-attestation

CosmWasm contract that verifies Intel TDX attestation quotes on-chain using DCAP (Data Center Attestation Primitives). It performs full cryptographic quote verification via the `dcap-qvl` library, replays the RTMR3 event log, checks TDX measurements, validates deterministic event hashes, and optionally binds a response body to the quote's `report_data`.

Deployed on **xion-testnet-2** as code ID `2000`.

## What It Does

Given a raw TDX quote, Intel PCS collateral, and an event log, the contract:

1. **Verifies the DCAP quote** — full certificate chain validation, TCB status check, and ECDSA signature verification using the CosmWasm `secp256r1_verify` host function.
2. **Replays RTMR3** — recomputes the RTMR3 measurement register by replaying the SHA-384 hash chain from the event log entries, then compares against the quoted value.
3. **Checks measurements** — compares `mr_td`, `rtmr1`, `rtmr2` (and optionally `rtmr0`) from the quote against expected values stored in the contract.
4. **Validates events** — checks that deterministic event payloads (`compose-hash`, `os-image-hash`) match expected values.
5. **Binds response body** (optional) — if a `response_body` is provided, verifies that `SHA256(response_body)` matches `report_data[..32]` from the TDX report (for bodies > 64 bytes) or that the body matches `report_data` directly (for bodies <= 64 bytes).
6. **Stores the result** — saves a `VerificationRecord` keyed by `SHA256(quote)` hex, queryable by anyone.

## Verification Pipeline

```
quote + collateral + event_log + response_body (optional)
  │
  ├─ dcap-qvl::verify()       → quote_verified, tcb_status
  ├─ rtmr::replay_rtmr3()     → rtmr3_verified
  ├─ check_measurements()      → measurements_verified
  ├─ validate_events()         → events_verified
  └─ SHA256(response_body)     → response_body_verified
  │
  └─ all_passed = all of the above
```

## Messages

### InstantiateMsg

```json
{
  "admin": "xion1...",                          // optional, defaults to sender
  "expected_measurements": {                     // optional
    "mr_td": "f06dfda6...",
    "rtmr1": "c0445b70...",
    "rtmr2": "5c993ed2...",
    "rtmr0": null,                               // optional
    "check_rtmr0": false
  },
  "expected_events": {                           // optional
    "compose_hash": "a813afbc...",
    "os_image_hash": "ead0c34c..."
  }
}
```

### ExecuteMsg

#### VerifyAttestation

```json
{
  "verify_attestation": {
    "quote": "<base64>",
    "collateral": "<base64>",
    "event_log": [
      { "event": "compose-hash", "payload": "<base64>" },
      { "event": "os-image-hash", "payload": "<base64>" },
      { "event": "app-compose", "payload": "<base64>" }
    ],
    "response_body": "<base64>"
  }
}
```

All binary fields are base64-encoded. `response_body` is optional (set to `null` to skip report_data binding).

Response attributes emitted on success:

| Attribute | Description |
|---|---|
| `action` | `"verify_attestation"` |
| `quote_hash` | SHA256 hex of the raw quote bytes |
| `tcb_status` | e.g. `"UpToDate"`, `"SWHardeningNeeded"` |
| `all_passed` | `"true"` or `"false"` |
| `rtmr3_verified` | `"true"` or `"false"` |
| `measurements_verified` | `"true"` or `"false"` |
| `events_verified` | `"true"` or `"false"` |
| `response_body_verified` | `"true"` or `"false"` |

#### SetExpectedMeasurements (admin only)

```json
{
  "set_expected_measurements": {
    "mr_td": "f06dfda6...",
    "rtmr1": "c0445b70...",
    "rtmr2": "5c993ed2...",
    "rtmr0": null,
    "check_rtmr0": false
  }
}
```

#### SetExpectedEvents (admin only)

```json
{
  "set_expected_events": {
    "compose_hash": "a813afbc...",
    "os_image_hash": "ead0c34c..."
  }
}
```

### QueryMsg

#### GetVerification

```json
{ "get_verification": { "quote_hash": "abc123..." } }
```

Returns a `VerificationRecord`:

```json
{
  "quote_verified": true,
  "rtmr3_verified": true,
  "measurements_verified": true,
  "events_verified": true,
  "all_passed": true,
  "tcb_status": "UpToDate",
  "advisory_ids": [],
  "mr_td": "f06dfda6...",
  "rtmr0": "...",
  "rtmr1": "c0445b70...",
  "rtmr2": "5c993ed2...",
  "rtmr3": "...",
  "report_data": "...",
  "response_body_verified": true,
  "response_body_hash": "abc123...",
  "mismatches": [],
  "verifier": "xion1...",
  "block_height": 12345,
  "block_time": 1700000000
}
```

#### GetConfig / GetExpectedMeasurements / GetExpectedEvents

```json
{ "get_config": {} }
{ "get_expected_measurements": {} }
{ "get_expected_events": {} }
```

## How to Get the Input Values

### 1. Quote

Fetch from a running dstack instance's attestation endpoint:

```bash
curl https://<dstack-app-url>/attestation
# Returns: { "quote": "<base64>" }
```

The quote is a raw Intel TDX v4 quote, base64-encoded.

### 2. Collateral

Fetch from Intel's Provisioning Certification Service (PCS) using the `dcap-qvl` library. The collateral must be serialized with `serde_json::to_vec()` to preserve `serde_bytes` fields correctly.

```rust
let collateral = dcap_qvl::collateral::get_collateral_from_pcs(&quote_bytes).await?;
let collateral_bytes = serde_json::to_vec(&collateral)?;
// base64-encode collateral_bytes for the contract message
```

Do **not** use custom JSON serialization — the collateral contains binary fields annotated with `serde_bytes` that must be serialized as byte arrays, not strings.

### 3. Event Log

Fetch from the dstack instance's info endpoint (port 8090):

```bash
curl https://<dstack-info-url>/
# HTML page containing event_log JSON
```

Parse the `event_log` array from the HTML, filter to `imr == 3` entries (RTMR3 events only), and convert each entry:

```rust
// Raw format from dstack:
// { "imr": 3, "event_type": 12, "event": "compose-hash", "event_payload": "a813af..." }

// Contract format:
// { "event": "compose-hash", "payload": "<base64 of hex-decoded event_payload>" }
```

The `payload` field in the contract message is the base64 encoding of the raw bytes (hex-decode the `event_payload` from dstack, then base64-encode).

### 4. Expected Measurements

Get from the dstack info page or by inspecting a known-good quote. These are hex-encoded 48-byte (384-bit) register values:

- **`mr_td`** — TD measurement (identifies the TD configuration)
- **`rtmr1`** — Runtime measurement register 1 (OS kernel)
- **`rtmr2`** — Runtime measurement register 2 (OS userspace)
- **`rtmr0`** — Runtime measurement register 0 (firmware, optional)

### 5. Expected Events

Deterministic hashes from the dstack compose configuration:

- **`compose_hash`** — SHA256 of the docker-compose configuration
- **`os_image_hash`** — SHA256 of the OS image

These are hex strings matching the `event_payload` of the corresponding event log entries.

### 6. Response Body (optional)

The raw HTTP response body from the dstack app when called with `?attest=true`. The TEE middleware computes `SHA256(response_body)` and places it in `report_data[..32]`, binding the response to the attestation quote.

## Build

```bash
docker run --rm \
  -v $(pwd):/code \
  -v /path/to/dcap-qvl:/dcap-qvl \
  --mount type=volume,source=dstack_attestation_cache,target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/optimizer:0.17.0
```

The contract depends on `dcap-qvl` via a path reference, so the dcap-qvl directory must be mounted into the Docker container at `/dcap-qvl`. Run `cargo update` before the Docker build (it uses `--locked`).

Output: `artifacts/dstack_attestation_contract.wasm`

## Deploy

### Store

```bash
xiond tx wasm store artifacts/dstack_attestation_contract.wasm \
  --from <key> --keyring-backend test \
  --node https://rpc.xion-testnet-2.burnt.com:443 \
  --chain-id xion-testnet-2 \
  --gas 20000000 --fees 500000uxion \
  -y --output json
```

### Instantiate

```bash
xiond tx wasm instantiate <code-id> '{
  "expected_measurements": {
    "mr_td": "f06dfda6...",
    "rtmr1": "c0445b70...",
    "rtmr2": "5c993ed2...",
    "rtmr0": null,
    "check_rtmr0": false
  },
  "expected_events": {
    "compose_hash": "a813afbc...",
    "os_image_hash": "ead0c34c..."
  }
}' \
  --label "dstack-attestation" \
  --from <key> --admin <admin-address> \
  --keyring-backend test \
  --node https://rpc.xion-testnet-2.burnt.com:443 \
  --chain-id xion-testnet-2 \
  --gas 500000 --fees 50000uxion \
  -y --output json
```

### Verify

```bash
xiond tx wasm execute <contract-address> '{
  "verify_attestation": {
    "quote": "<base64>",
    "collateral": "<base64>",
    "event_log": [...],
    "response_body": "<base64>"
  }
}' \
  --from <key> --keyring-backend test \
  --node https://rpc.xion-testnet-2.burnt.com:443 \
  --chain-id xion-testnet-2 \
  --gas 50000000 --fees 500000uxion \
  -y --output json
```

The verification TX needs ~50M gas due to the DCAP certificate chain validation.

### Query Result

```bash
xiond q wasm contract-state smart <contract-address> \
  '{"get_verification":{"quote_hash":"<sha256-hex-of-quote>"}}' \
  --node https://rpc.xion-testnet-2.burnt.com:443
```

## Composing with Other Contracts

The contract is designed to be called via `SubMsg` from upstream contracts (e.g. the `clearance` contract). The pattern:

1. Upstream sends `SubMsg::reply_on_success(WasmMsg::Execute { VerifyAttestation { ... } }, REPLY_ID)`
2. In the reply handler, extract `quote_hash` from the `wasm` event attributes
3. Query `GetVerification { quote_hash }` to get the full record
4. Apply business logic on top of the verification result

## E2E Tests

The `dstack-attestation-test` crate runs a full end-to-end test against a live chain:

```bash
cd contracts/dstack-attestation-test
# Set XION_TESTNET_MNEMONIC in .env or environment
cargo test --test verify_on_chain -- --nocapture
```

This stores the WASM, instantiates the contract, fetches a live quote + collateral + event log, submits verification, and asserts all checks pass.
