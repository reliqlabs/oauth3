# Deployment Notes

Hard-won lessons from deploying oauth3 (Rust + Nix + SP1/gnark + Phala dstack TEE).

## Building the Docker Image

Docker images are built entirely through Nix: `nix build .#dockerImage` (on Linux only — `dockerTools.buildLayeredImage` uses `fakeroot` which doesn't work on macOS). CI runs this on every push.

The Nix build compiles the Rust binary, bundles SP1 GPU server + Groth16 circuit artifacts, and produces a layered OCI image.

### gnark FFI Build Requirements

SP1's Groth16 prover uses gnark (Go) via CGO. This creates several Nix build challenges:

**Go cache directories** — Go needs writable `GOCACHE` and `GOPATH`. Nix sandbox makes `$HOME` read-only:

```nix
GOCACHE = "/tmp/go-cache";
GOPATH = "/tmp/go-path";
```

**bindgen + libclang** — sp1-recursion-gnark-ffi uses `bindgen` for C header bindings. Without both of these, bindgen fails to find `stddef.h`:

```nix
LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.lib.versions.major pkgs.llvmPackages.libclang.version}/include";
```

**Nix sandbox** — Go module downloads during the gnark FFI build are blocked by the Nix sandbox. CI must use `sandbox = false`.

**protobuf** — `sp1-prover-types` builds protobuf definitions. Add `protobuf` to `nativeBuildInputs`.

**LTO and memory** — Fat LTO with 1 codegen unit OOMs on CI runners with <16GB RAM:

```nix
CARGO_PROFILE_RELEASE_LTO = "thin";
CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "16";
```

## Nix Docker Images + NVIDIA GPUs

### The Core Problem: No Standard FHS

Nix `dockerTools.buildLayeredImage` produces images with no `/usr/lib/`, `/usr/bin/`, etc. — everything lives in `/nix/store/`. This breaks nvidia-container-toolkit in two ways:

1. **Silent mount failure** — nvidia-container-toolkit bind-mounts CUDA libraries into FHS paths (`/usr/lib/x86_64-linux-gnu/`, `/usr/lib64/`). If these directories don't exist, the toolkit **silently skips the mount**. The container starts fine but has no GPU access. Zero error messages.

2. **Misdiagnosed errors** — Without the injected CUDA libs, GPU operations fail with vague errors like "operation not supported" from `cudaDeviceGetMemPool()`. This looks like NVIDIA Confidential Computing (CC) mode blocking CUDA, but the real root cause is the missing libraries. We spent significant time chasing a CC-mode red herring before Phala devrel identified this.

Fix in `flake.nix`:

```nix
extraCommands = ''
  mkdir -p usr/lib/x86_64-linux-gnu
  mkdir -p usr/lib64
  mkdir -p usr/bin
  mkdir -p usr/lib  # for manual mounts (see below)
'';
```

### Manual CUDA Library Mounts (The Real Fix)

Even with FHS directories created, nvidia-container-runtime's automatic injection remains unreliable with Nix images. The proven fix from Phala devrel is to **manually mount the specific `.so` files** from the dstack VM host into the container.

Required libraries (driver version `570.172.08` on current dstack-nvidia-dev):

```yaml
volumes:
  # Core CUDA driver
  - /usr/lib/libcuda.so.570.172.08:/usr/lib/libcuda.so.570.172.08:ro
  - /usr/lib/libcuda.so.570.172.08:/usr/lib/libcuda.so.1:ro
  # CC-mode security attestation (required for GPU in TEE)
  - /usr/lib/libnvidia-pkcs11.so.570.172.08:/usr/lib/libnvidia-pkcs11.so.570.172.08:ro
  - /usr/lib/libnvidia-pkcs11-openssl3.so.570.172.08:/usr/lib/libnvidia-pkcs11-openssl3.so.570.172.08:ro
  # PTX JIT compiler (required for ZK proof generation)
  - /usr/lib/libnvidia-ptxjitcompiler.so.570.172.08:/usr/lib/libnvidia-ptxjitcompiler.so.570.172.08:ro
  - /usr/lib/libnvidia-ptxjitcompiler.so.570.172.08:/usr/lib/libnvidia-ptxjitcompiler.so.1:ro
```

The libraries break down into three categories:

| Library | Purpose | Why needed |
|---------|---------|------------|
| `libcuda.so` | CUDA driver API | Core GPU access — nothing works without this |
| `libnvidia-pkcs11*.so` | CC-mode attestation | GPU security handshake in TEE environments |
| `libnvidia-ptxjitcompiler.so` | PTX JIT compiler | Compiles GPU kernels at runtime — ZK provers need this |

The PTX JIT compiler was a key missing piece. Without it, CUDA initializes but kernel launches fail — which is exactly what ZK proving does.

### LD_LIBRARY_PATH

Binaries won't find CUDA libs unless `LD_LIBRARY_PATH` includes the mount paths. All three are needed:

```nix
Env = [ "LD_LIBRARY_PATH=/usr/lib64:/usr/lib/x86_64-linux-gnu:/usr/lib" ];
```

- `/usr/lib64` — dstack Yocto host auto-injection path
- `/usr/lib/x86_64-linux-gnu` — Debian host auto-injection path
- `/usr/lib` — manual mount path (from compose volumes above)

### libcudart.so vs libcuda.so

These are different libraries with different sourcing:

| Library | What | Source |
|---------|------|--------|
| `libcuda.so` | CUDA driver API | Host (manual mount or nvidia-container-toolkit) |
| `libnvidia-ml.so` | NVIDIA Management Library | Host (nvidia-container-toolkit) |
| `libcudart.so` | CUDA runtime API | Must be bundled in the image |

nvidia-container-toolkit only provides driver-level libraries. The CUDA runtime (`libcudart.so`) must be in the image. In Nix:

```nix
buildInputs = [
  pkgs.cudaPackages.cuda_cudart.lib  # libcudart.so
];
```

This requires `config.allowUnfree = true` in the nixpkgs import.

### HOME Must Be Writable

SP1 SDK writes to `$HOME/.sp1/` at runtime (circuit artifacts, gpu-server binary). Set `HOME=/tmp`.

### Missing Utilities

Nix images don't include `ldd`, `nvidia-smi`, `grep`, or `find` by default. Add `bashInteractive` and `coreutils` to `contents` for basic debugging. Don't expect `nvidia-smi` to work — it's a host binary that needs the standard glibc dynamic linker, which Nix images don't have.

## SP1 GPU Server (sp1-gpu-server)

### Binary Patching with autoPatchelfHook

The pre-built `sp1-gpu-server` binary (x86_64 Linux, from SP1 GitHub releases) is dynamically linked against glibc and libstdc++. In a Nix image, the standard dynamic linker path (`/lib64/ld-linux-x86-64.so.2`) doesn't exist. Use `autoPatchelfHook` to rewrite the binary's interpreter and RPATH:

```nix
sp1Artifacts = pkgs.stdenv.mkDerivation {
  nativeBuildInputs = [ pkgs.autoPatchelfHook ];
  buildInputs = [
    pkgs.stdenv.cc.cc.lib              # libstdc++
    pkgs.cudaPackages.cuda_cudart.lib  # libcudart.so
  ];
  # These are injected at runtime by nvidia-container-toolkit — NOT in image
  autoPatchelfIgnoreMissingDeps = [ "libcuda.so.*" "libnvidia-ml.so.*" ];
};
```

### Version Shim

SP1 SDK checks `sp1-gpu-server --version` and tries to download a matching version if it doesn't match. Inside a container, this triggers `systemctl --user stop` (doesn't exist) or network downloads (may be blocked). Prevent with a wrapper:

```nix
sp1GpuServerWrapper = pkgs.writeShellScriptBin "sp1-gpu-server" ''
  if [ "$1" = "--version" ]; then
    echo "6.0.2"
    exit 0
  fi
  export LD_LIBRARY_PATH="/usr/lib64:/usr/lib/x86_64-linux-gnu:''${LD_LIBRARY_PATH:-}"
  exec "${sp1Artifacts}/sp1/bin/sp1-gpu-server" "$@"
'';
```

Symlink the wrapper into `$HOME/.sp1/bin/sp1-gpu-server` at container startup (the entrypoint script does this).

### CUDA_VISIBLE_DEVICES

`sp1-gpu-server` requires `CUDA_VISIBLE_DEVICES` as a **single numeric device ID** (e.g., `0`). It parses this as a `u32`:

- `CUDA_VISIBLE_DEVICES=all` → ParseIntError ("InvalidDigit")
- `CUDA_VISIBLE_DEVICES=0,1` → ParseIntError
- Unset → panic ("must be set: NotPresent")

Set in Docker env: `CUDA_VISIBLE_DEVICES=0`.

### Groth16 Circuit Artifacts

SP1 Groth16 proving requires ~7.8GB of pre-extracted circuit artifacts. Don't rely on runtime download — bundle them in the image and point to them:

```nix
"SP1_GROTH16_CIRCUIT_PATH=${sp1Artifacts}/sp1/circuits/groth16"
```

Download: `https://sp1-circuits.s3-us-east-2.amazonaws.com/v6.0.0-groth16.tar.gz` (~5.9GB compressed).

## NVIDIA Confidential Computing (CC) Mode

Phala dstack TEE nodes run NVIDIA GPUs in Confidential Computing mode. CC-mode restricts certain CUDA features:

- `cudaDeviceGetMemPool()` — disabled (stream-ordered memory pools)
- Unified memory — disabled or restricted
- Peer-to-peer GPU access — disabled

### The Misdiagnosis

We initially believed CC-mode fundamentally blocked GPU proving. SP1's `sp1-gpu-server` was failing with `cudaDeviceGetMemPool()` → "operation not supported", which looked like a CC-mode restriction.

**The actual root cause was different**: nvidia-container-runtime was silently failing to inject CUDA libraries into the Nix image (no FHS directories). Without `libcuda.so`, `libnvidia-pkcs11*.so`, and `libnvidia-ptxjitcompiler.so`, CUDA partially initializes but fails at operations that need the driver — producing errors that *look like* CC-mode restrictions but are actually missing library errors.

### The Fix (from Phala devrel)

Two changes resolved GPU proving in CC-mode TEE:

1. **Manual library mounts** — Mount `libcuda.so`, `libnvidia-pkcs11*.so` (CC-mode attestation), and `libnvidia-ptxjitcompiler.so` (PTX JIT compiler) directly from the VM host into the container via compose volumes. See [Manual CUDA Library Mounts](#manual-cuda-library-mounts-the-real-fix) above.

2. **dstack image upgrade to v0.5.6** — Resolves PTX JIT compiler compatibility issues on the host side.

With both changes, GPU proving works in CC-mode TEE. The `cudaDeviceGetMemPool()` limitation may still apply to SP1's `sp1-gpu-server` (which uses stream-ordered memory pools), but gnark's icicle backend does not use that API and works correctly.

### Current Status

| Backend | CC-mode GPU | Notes |
|---------|-------------|-------|
| gnark-gpu (icicle) | Works | ~3-5s e2e with manual lib mounts |
| SP1 GPU (sp1-gpu-server) | Blocked | Uses `cudaDeviceGetMemPool()` — genuinely unsupported in CC-mode |
| SP1 CPU | Works | ~7 min on 24 vCPU |
| SP1 Network | Works | Remote GPU, needs funded account |

## Phala Cloud (dstack)

### Deploy / Update

```sh
# Deploy new or update existing CVM
phala deploy --cvm-id <UUID> --compose docker-compose.phala.yml -e .env.phala --wait

# Logs (returns JSON)
phala cvms logs <UUID> --json

# Status
phala cvms get <UUID> --json
```

CVM restarts take 60-90 seconds (stopping → stopped → starting → running). After `--wait` returns, give the app another 10-15 seconds to initialize (DB migrations, SP1 prover setup on first proof).

### GPU Compose Config

Both `runtime: nvidia` AND `deploy.resources.reservations` are needed:

```yaml
services:
  app:
    runtime: nvidia
    environment:
      NVIDIA_VISIBLE_DEVICES: all
      NVIDIA_DRIVER_CAPABILITIES: compute,utility
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu, compute, utility]
```

dstack's Docker `daemon.json` registers the nvidia runtime but does NOT set it as default. Without explicit `runtime: nvidia` in compose, the container gets no GPU — silently.

### Image Tag Caching

`phala deploy` won't pull a new image if the tag name is unchanged. Use SHA-specific tags (e.g., `feat-contract-464823a`) to force pulls. CI generates `type=sha,prefix={{branch}}-` tags.

### Proxy Timeout

Phala's reverse proxy has a ~7 minute connection timeout. Any synchronous HTTP request that takes longer will be killed. For slow provers (SP1 CPU), use the async job queue:

1. `?prove=true` → HTTP 202 Accepted with `{ "job_id": "...", "poll_url": "/prove/<id>" }`
2. Background worker processes the job (~7 min)
3. Client polls `GET /prove/{job_id}` for status

Fast provers (gnark-gpu, ~3-5s) can use `?prove=gnark-gpu-sync` for a synchronous inline response.

### dstack Socket for TEE Attestation

TDX quote generation requires the dstack Unix socket:

```yaml
volumes:
  - /var/run/dstack.sock:/var/run/dstack.sock
environment:
  DSTACK_SOCKET: /var/run/dstack.sock
```

### dstack Base Image Versions

| Version | Key change |
|---------|-----------|
| `dstack-nvidia-dev-0.5.4.1` | Initial GPU support |
| `dstack-nvidia-dev-0.5.6` | PTX JIT compiler compatibility fix — **required for ZK proving** |

Always use v0.5.6+ for GPU proof generation workloads.

### Infrastructure

| Node | Region | Specs | Type |
|------|--------|-------|------|
| prod5 | US-WEST-1 | 32 vCPU / 64GB | CPU |
| prod9 | US-WEST-1 | 32 vCPU / 64GB | CPU |
| gpu-use2 | US-EAST-1 | 24 vCPU / 192GB / 1x H200 141GB | GPU ($3.50/hr) |

Container names inside dstack are `dstack-app-1` and `dstack-db-1` (not `app` or `db`).

## SP1 v6 Proof Format

SP1 v6 Groth16 proofs are **352 bytes**, not the 256 you'd expect from standard Groth16. The extra 96 bytes are a Keccak commitment (SP1 v6 specific):

```
Bytes 0-31:     Ar.X    (G1 pi_a x)
Bytes 32-63:    Ar.Y    (G1 pi_a y)
Bytes 64-95:    Bs.X.A1 (G2 pi_b x imaginary)
Bytes 96-127:   Bs.X.A0 (G2 pi_b x real)
Bytes 128-159:  Bs.Y.A1 (G2 pi_b y imaginary)
Bytes 160-191:  Bs.Y.A0 (G2 pi_b y real)
Bytes 192-223:  Krs.X   (G1 pi_c x)
Bytes 224-255:  Krs.Y   (G1 pi_c y)
Bytes 256-287:  Commitment.X   (G1, Keccak commitment)
Bytes 288-319:  Commitment.Y   (G1, Keccak commitment)
Bytes 320-351:  CommitmentPok  (scalar, proof of knowledge)
```

gnark stores G2 coordinates as `[imaginary, real]` (A1 before A0), which is the opposite of SnarkJS convention `[real, imaginary]`. The conversion in `contracts/zkdcap/host/src/sp1.rs` handles this swap.

## Debugging Checklist

When GPU proving doesn't work in a new TEE deployment:

1. **Are GPU devices visible?** `ls /dev/nvidia*` — if missing, check compose `runtime: nvidia`
2. **Are CUDA libs present?** `ls /usr/lib/libcuda*` — if missing, add manual volume mounts in compose
3. **Is PTX JIT compiler present?** `ls /usr/lib/libnvidia-ptxjitcompiler*` — required for ZK kernel compilation
4. **Is LD_LIBRARY_PATH correct?** Must include `/usr/lib` (manual mounts), `/usr/lib64`, `/usr/lib/x86_64-linux-gnu`
5. **Is dstack base image >= v0.5.6?** Older versions have PTX JIT compatibility issues
6. **Can sp1-gpu-server start?** Run it manually with `--help` — if "not found", check autoPatchelfHook
7. **Does gnark-gpu work?** Test with `?prove=gnark-gpu-sync` first (simpler CUDA usage than SP1)
8. **Does CUDA init fully work?** If sp1-gpu-server fails with "operation not supported" after manual mounts are confirmed, that's a genuine CC-mode limitation for SP1 specifically
9. **Is CUDA_VISIBLE_DEVICES set correctly?** SP1 needs a single number like `0`; gnark uses `NVIDIA_VISIBLE_DEVICES: all`

---

## Deployment Log

Tracks what was deployed, when, and what changed.

### How to Verify

1. **Image digest**: `docker inspect --format='{{index .RepoDigests 0}}' <image>`
2. **Compose hash**: `sha256sum docker-compose.phala.yml`
3. **CVM attestation**: `curl <app-url>/info?attest=true` — verify RTMR3 matches expected measurements

### 2026-03-04 — GPU Fix: Manual CUDA Lib Mounts + dstack v0.5.6

- **Compose**: `docker-compose.phala.yml`
- **CVM**: `17473f941e79464abafbf2883eda9e29` (gpu-use2, US-EAST-1)
- **Root cause**: nvidia-container-runtime silently failed to inject CUDA libs into Nix image (no FHS paths). Misdiagnosed as CC-mode blocking CUDA.
- **Fix** (from Phala devrel):
  - Manual volume mounts for `libcuda.so`, `libnvidia-pkcs11*.so`, `libnvidia-ptxjitcompiler.so`
  - dstack base image upgraded to v0.5.6 (PTX JIT compiler compatibility)
  - Added `/usr/lib` to `LD_LIBRARY_PATH`
- **Result**: gnark-gpu proving now works in CC-mode TEE (~3-5s e2e)

### 2026-03-03 — DevProof Stage 1 Hardening

- **Image**: `ghcr.io/reliqlabs/oauth3:feat-contract-5bb39c9`
- **Compose**: `docker-compose.phala.yml`
- **CVM**: `17473f941e79464abafbf2883eda9e29` (gpu-use2, US-EAST-1)
- **Changes**:
  - Hardcoded OAuth provider endpoints (ISSUER, API_BASE_URL, TYPE, MODE, SCOPES) in compose — prevents operator redirect attacks
  - Pinned Docker image tag in compose (was `${DOCKER_IMAGE}` env var)
  - Cookie key derived from dstack KMS via `DeriveKey("oauth3/cookie-key")` — operator can no longer supply a known key
  - Removed `COOKIE_KEY_BASE64` from compose and `.env.phala`

### 2026-02-28 — gnark Long-Lived Server Mode

- **Image**: `ghcr.io/reliqlabs/oauth3:feat-contract-5bb39c9`
- **Compose**: `docker-compose.phala.yml`
- **Changes**:
  - Converted gnark prove binary from one-shot CLI to long-lived HTTP server
  - Added Content-Length header to gnark server response (avoid chunked encoding)
  - Separate gnark-cpu and gnark-gpu binaries (icicle build tag)
