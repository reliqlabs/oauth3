# TEE Attestation with Phala dstack

This application implements Phala Cloud's standard attestation pattern for verifiable TEE execution.

## Local Development Setup

### Run with Docker Compose (Recommended)

```bash
# Start all services including Phala simulator
docker-compose up

# Test the endpoints
curl http://localhost:8080/info
curl http://localhost:8080/attestation
```

The simulator runs in a container and shares a volume with the app for communication

## Attestation Endpoints

### `GET /info`

Returns application configuration that can be verified:

```bash
curl http://localhost:8080/info
```

Response:
```json
{
  "version": "0.1.0",
  "name": "oauth3",
  "build_info": null
}
```

### `GET /attestation`

Returns TDX attestation quote proving this exact code runs in a TEE:

```bash
curl http://localhost:8080/attestation
```

Response:
```json
{
  "quote": "<base64_encoded_tdx_quote>",
  "eventLog": "..."
}
```

The quote's `reportData` field contains a hash of the `/info` response, binding the attestation to the code version.

## Verification Flow

Clients verify TEE execution in two steps:

1. **Hardware Verification**: Verify the `quote` using Intel TDX verification
   - Proves code runs in genuine Intel TDX hardware
   - In simulator: quote is mock but API structure matches production

2. **Code Verification**:
   - Fetch `/info` and hash the response (SHA256)
   - Extract `reportData` from the quote
   - Verify hash matches `reportData`
   - Proves the exact code version running

## Production on Phala Cloud

When deployed to Phala Cloud:

1. Simulator quotes become real Intel TDX hardware quotes
2. TLS certificates also get attestation at `https://your-domain.com/evidences/`
3. Same `/attestation` and `/info` endpoints work identically

No code changes needed for production deployment.

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ GET /attestation
       │ GET /info
       ▼
┌─────────────┐
│  oauth3 API │
└──────┬──────┘
       │ Unix socket
       ▼
┌─────────────┐
│   dstack    │  ← Simulator (local) or Intel TDX (prod)
│   socket    │
└─────────────┘
```

## References

- [Phala Cloud Attestation Docs](https://docs.phala.com/phala-cloud/phala-cloud-user-guides/building-with-tee/generate-ra-report)
- [dstack GitHub](https://github.com/Phala-Network/dstack)
