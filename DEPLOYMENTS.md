# Deployment Log

Tracks what was deployed, when, and what changed. Each entry should include enough information to reproduce or verify the deployment.

## How to Verify

1. **Image digest**: `docker inspect --format='{{index .RepoDigests 0}}' <image>`
2. **Compose hash**: `sha256sum docker-compose.phala.yml`
3. **CVM attestation**: `curl <app-url>/info?attest=true` — verify RTMR3 matches expected measurements

## Deployments

### 2026-03-03 — DevProof Stage 1 Hardening

- **Image**: `ghcr.io/reliqlabs/oauth3:feat-contract-5bb39c9`
- **Compose**: `docker-compose.phala.yml`
- **CVM**: `17473f941e79464abafbf2883eda9e29` (gpu-use2, US-EAST-1)
- **Changes**:
  - Hardcoded OAuth provider endpoints (ISSUER, API_BASE_URL, TYPE, MODE, SCOPES) in compose — prevents operator redirect attacks
  - Pinned Docker image tag in compose (was `${DOCKER_IMAGE}` env var)
  - Cookie key derived from dstack KMS via `DeriveKey("oauth3/cookie-key")` — operator can no longer supply a known key
  - Removed `COOKIE_KEY_BASE64` from compose and `.env.phala`
  - Created this deployment log

### 2026-02-28 — gnark Long-Lived Server Mode

- **Image**: `ghcr.io/reliqlabs/oauth3:feat-contract-5bb39c9`
- **Compose**: `docker-compose.phala.yml`
- **Changes**:
  - Converted gnark prove binary from one-shot CLI to long-lived HTTP server
  - Added Content-Length header to gnark server response (avoid chunked encoding)
  - Separate gnark-cpu and gnark-gpu binaries (icicle build tag)
