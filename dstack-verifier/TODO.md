# TODO: Integrate Official dstack-verifier

## Current Status (2026-01-25)

Using embedded lightweight implementation instead of official dstack-verifier.

## Blockers

### Official dstack-verifier Issues:

1. **v0.5.5** (latest release)
   - ❌ Binary-only (HTTP server, no library exports)
   - ❌ Compilation error in `ra-tls` dependency
   - Error: `KeyRejected` from `ring` crate doesn't implement `std::error::Error`
   - Location: `ra-tls/src/cert.rs:147`

2. **main branch** (commit 745b168, as of 2026-01-25)
   - ❌ Compilation error in `tdx-attest` dependency
   - Error: `unresolved import cc_eventlog::TdxEventLog`
   - Location: `tdx-attest/src/dummy.rs:5`

## Integration Checklist

When checking for updates, verify:

- [ ] New release published at https://github.com/Dstack-TEE/dstack/releases
- [ ] `verifier/Cargo.toml` has `[lib]` section (not just binary)
- [ ] Test compilation:
  ```bash
  git clone --depth 1 --branch vX.X.X https://github.com/Dstack-TEE/dstack
  cd dstack
  cargo build -p dstack-verifier
  cargo build -p ra-tls
  cargo build -p tdx-attest
  ```
- [ ] Verify public API exports in `verifier/src/lib.rs`
- [ ] Check that `CvmVerifier::verify()` method is public

## Integration Steps (once fixed)

1. Update `oauth3/Cargo.toml`:
   ```toml
   dstack-verifier = { git = "https://github.com/Dstack-TEE/dstack", tag = "vX.X.X" }
   ```

2. Update `src/web/handlers/attestation.rs`:
   ```rust
   use dstack_verifier::{CvmVerifier, VerificationRequest};

   let verifier = CvmVerifier::new(
       "/tmp/dstack-cache".to_string(),
       "https://dstack-sim.phala.network/sgx/dev/v1".to_string(),
       Duration::from_secs(300),
   );
   ```

3. Adapt request format to match official API:
   - Official expects: `{ quote: String, event_log: String, vm_config: String }`
   - Currently using: `{ attestation: {...}, info: {...} }`

4. Remove embedded `dstack-verifier` directory

## Benefits of Official Verifier

- ✅ OS image hash verification (via dstack-mr)
- ✅ Official Phala Network implementation
- ✅ Active maintenance and updates
- ✅ More comprehensive ACPI tables support
- ✅ Better RTMR debugging output

## Current Implementation Features

✅ TDX quote verification via dcap-qvl v0.3 (same as official)
✅ TCB status validation
✅ Report data verification
✅ RTMR event log replay
❌ OS image hash verification (requires dstack-mr)
