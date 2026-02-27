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
Verifies a TDX attestation quote using the official dstack-verifier v0.5.6.

Accepts either format:

**Versioned attestation (from dstack Attest API):**
```json
{
  "attestation": "hex-encoded-attestation"
}
```

**Quote + event log (from dstack GetQuote API):**
```json
{
  "quote": "hex-encoded-quote",
  "event_log": "hex-encoded-event-log",
  "vm_config": "json-vm-config-string"
}
```

**Response:**
```json
{
  "is_valid": true,
  "details": {
    "quote_verified": true,
    "event_log_verified": true,
    "os_image_hash_verified": true,
    "report_data": "hex-encoded-64-byte-report-data",
    "tcb_status": "UpToDate",
    "advisory_ids": [],
    "app_info": {
      "app_id": "hex-string",
      "compose_hash": "hex-string",
      "instance_id": "hex-string",
      "device_id": "hex-string",
      "mrtd": "hex-string",
      "rtmr0": "hex-string",
      "rtmr1": "hex-string",
      "rtmr2": "hex-string",
      "rtmr3": "hex-string",
      "mr_system": "hex-string",
      "mr_aggregated": "hex-string",
      "os_image_hash": "hex-string",
      "key_provider_info": "hex-string"
    }
  },
  "reason": null
}
```

## Verification Implementation

Uses the official [dstack-verifier v0.5.6](https://github.com/Dstack-TEE/dstack/tree/v0.5.6/verifier) library, which provides:

- TDX quote cryptographic verification (via dcap-qvl)
- TCB status validation
- RTMR event log replay verification
- OS image hash verification (via dstack-mr)

## Verification Flow

```
Client Request
     ↓
1. Parse quote/attestation
     ↓
2. Verify with dcap-qvl
   - Cryptographic verification
   - Certificate chain validation
   - TCB status check
     ↓
3. Replay RTMR event log
   - RTMR3: digest + payload integrity
   - RTMR 0-2: digest verification only
     ↓
4. Verify OS image hash
   - Download OS image (cached)
   - Compute expected MRs via dstack-mr
   - Compare against verified quote MRs
     ↓
5. Decode app_info from event log
     ↓
6. Return verification response
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DSTACK_IMAGE_CACHE_DIR` | `/tmp/dstack-verifier/cache` | Directory for cached OS images |
| `DSTACK_IMAGE_DOWNLOAD_URL` | `https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz` | URL template for OS images |
| `DSTACK_IMAGE_DOWNLOAD_TIMEOUT_SECS` | `300` | Download timeout in seconds |
| `DSTACK_PCCS_URL` | (Intel default) | PCCS URL for quote verification |
| `DSTACK_SOCKET` | - | Unix socket path for dstack (production) |
| `DSTACK_ENDPOINT` | `http://simulator:8090` | HTTP endpoint for dstack (dev) |

## Testing

Run verification tests:
```bash
cargo test verify_endpoint
```

## References

- [Phala Cloud TEE Documentation](https://docs.phala.com/phala-cloud/phala-cloud-user-guides/building-with-tee)
- [Intel TDX Specification](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- [dstack Project](https://github.com/Dstack-TEE/dstack)
- [dstack-verifier README](https://github.com/Dstack-TEE/dstack/tree/v0.5.6/verifier)
- [dcap-qvl Library](https://github.com/automata-network/dcap-qvl)
