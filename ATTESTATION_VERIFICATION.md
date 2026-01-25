# TDX Attestation Verification

## Overview

This service provides TDX attestation generation and verification for oauth3 running in a Trusted Execution Environment (TEE).

## Endpoints

### GET /info
Returns application information that is bound to the attestation quote.

**Response:**
```json
{
  "version": "0.1.0",
  "name": "oauth3",
  "build_info": "2026-01-25T12:00:00Z"
}
```

### GET /attestation
Generates a TDX attestation quote with the `/info` response hash embedded in reportData.

**Response:**
```json
{
  "quote": "base64-encoded-tdx-quote",
  "eventLog": "json-event-log",
  "vmConfig": "json-vm-config"
}
```

### POST /verify
Verifies a TDX attestation quote and returns detailed verification results.

**Request:**
```json
{
  "attestation": {
    "quote": "base64-encoded-tdx-quote",
    "eventLog": "json-event-log"
  },
  "info": {
    "version": "0.1.0",
    "name": "oauth3"
  }
}
```

**Response:**
```json
{
  "quote_valid": true,
  "report_data_valid": true,
  "tcb_status": "UpToDate",
  "advisory_ids": [],
  "rtmr_valid": true,
  "info": { "version": "0.1.0", "name": "oauth3" }
}
```

## Verification Implementation

### Current: Embedded Verifier

We use a lightweight embedded implementation located in `dstack-verifier/` that provides:

- ✅ TDX quote cryptographic verification (via dcap-qvl v0.3)
- ✅ TCB status validation
- ✅ Report data binding verification
- ✅ RTMR event log replay verification
- ❌ OS image hash verification (not available)

### Why Not Official dstack-verifier?

As of 2026-01-25, the official dstack-verifier cannot be used directly:

1. **v0.5.5 (latest release)**
   - Binary-only HTTP server (no library exports)
   - Compilation errors in `ra-tls` dependency

2. **main branch**
   - Compilation errors in `tdx-attest` dependency

See `dstack-verifier/TODO.md` for integration checklist and tracking.

## Verification Flow

```
Client Request
     ↓
1. Parse quote (base64 → bytes)
     ↓
2. Verify with dcap-qvl
   - Cryptographic verification
   - Certificate chain validation
   - TCB status check
     ↓
3. Extract reportData from quote
     ↓
4. Compute expected reportData
   - SHA-256 hash of info JSON
   - Zero-pad to 64 bytes
     ↓
5. Compare reportData
     ↓
6. Replay RTMR event log
   - SHA-384 hash chain
   - Compare with quote RTMRs
     ↓
7. Return verification report
```

## Dependencies

- **dcap-qvl v0.3**: Intel TDX quote verification
- **hex**: Quote decoding (dstack returns hex format)
- **base64**: Quote encoding for standard format
- **sha2**: reportData hashing and RTMR replay

## Configuration

### PCCS URL
Default: `https://pccs.phala.network`

The Phala PCCS (Provisioning Certificate Caching Service) provides Intel collateral for quote verification.

### Quote Format
- **Input from dstack**: Hex-encoded
- **Storage/API**: Base64-encoded (standard TDX format)
- **Verification**: Converted to bytes for dcap-qvl

## Testing

Run verification tests:
```bash
cargo test verify_endpoint
```

Test with real production quote:
```bash
cargo test verify_endpoint_accepts_attestation_request
```

## Future Work

1. **Integrate official dstack-verifier** once build issues are resolved
   - Track at: https://github.com/Dstack-TEE/dstack/releases
   - See: `dstack-verifier/TODO.md`

2. **Add OS image verification** when dstack-mr becomes available
   - Requires working ra-tls and dstack-mr dependencies
   - Provides stronger security guarantees

3. **Configurable verification policies**
   - Optional RTMR[0] (OS hash) verification
   - Optional compose hash verification
   - Optional domain verification

## References

- [Phala Cloud TEE Documentation](https://docs.phala.com/phala-cloud/phala-cloud-user-guides/building-with-tee)
- [Intel TDX Specification](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- [dstack Project](https://github.com/Dstack-TEE/dstack)
- [dcap-qvl Library](https://github.com/automata-network/dcap-qvl)
