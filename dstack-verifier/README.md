# dstack-verifier

Rust library for verifying Phala dstack TDX attestation quotes.

## Features

- Parse and verify Intel TDX attestation quotes
- Verify report data matches application info
- Compatible with Phala dstack attestation format

## Usage

```rust
use dstack_verifier::{AttestationVerifier, AttestationResponse, InfoResponse};

let verifier = AttestationVerifier::new();

// From API responses
let attestation: AttestationResponse = /* fetch from /attestation */;
let info: InfoResponse = /* fetch from /info */;

// Verify
let report = verifier.verify_attestation(&attestation, &info)?;

assert!(report.quote_valid);
assert!(report.report_data_valid);
```

## Verification Process

1. **Quote Parsing**: Decodes base64 quote and parses TDX structure
2. **Report Data Verification**: Compares quote's `reportData` with hash of application info

The library matches the dstack client's report data calculation:
- Data ≤ 64 bytes: zero-padded to 64 bytes
- Data > 64 bytes: SHA256 hash (32 bytes)

## Dependencies

- `tdx-quote`: TDX quote parsing
- `base64`: Quote decoding
- `sha2`: Report data hashing
- `serde`/`serde_json`: JSON handling
