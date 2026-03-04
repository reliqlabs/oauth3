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

Nix `dockerTools.buildLayeredImage` produces images with no `/usr/lib/`, `/usr/bin/`, etc. — everything lives in `/nix/store/`. This breaks nvidia-container-toolkit.

**nvidia-container-toolkit** bind-mounts CUDA libraries into `/usr/lib/x86_64-linux-gnu/` (Debian hosts) or `/usr/lib64/` (Yocto/dstack hosts). If these directories don't exist in the image, the toolkit **silently skips the mount** — the container starts fine but has no GPU access. There are zero error messages. You'll spend hours wondering why `/dev/nvidia*` exists but CUDA doesn't work.

Fix in `flake.nix`:

```nix
extraCommands = ''
  mkdir -p usr/lib/x86_64-linux-gnu
  mkdir -p usr/lib64
  mkdir -p usr/bin
'';
```

### LD_LIBRARY_PATH

Even with the directories created, binaries won't find the injected CUDA libs unless `LD_LIBRARY_PATH` includes them. Both paths are needed — dstack's Yocto host uses `/usr/lib64/`, Debian-based hosts use `/usr/lib/x86_64-linux-gnu/`:

```nix
Env = [ "LD_LIBRARY_PATH=/usr/lib64:/usr/lib/x86_64-linux-gnu" ];
```

### libcudart.so vs libcuda.so

These are different libraries with different sourcing:

| Library | What | Source |
|---------|------|--------|
| `libcuda.so` | CUDA driver API | Injected by nvidia-container-toolkit from host |
| `libnvidia-ml.so` | NVIDIA Management Library | Injected by nvidia-container-toolkit from host |
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

**This is the single biggest blocker for GPU proving in TEE environments.**

Phala dstack TEE nodes run NVIDIA GPUs in Confidential Computing mode. CC-mode disables several CUDA features to prevent GPU memory side-channel attacks:

- `cudaDeviceGetMemPool()` — disabled (stream-ordered memory pools)
- Unified memory — disabled or restricted
- Peer-to-peer GPU access — disabled

SP1 v6's GPU backend (`sp1-gpu-server`) unconditionally calls `cudaDeviceGetMemPool()` and panics when it returns "operation not supported". The error chain:

```
1. sp1-gpu-server starts, initializes CUDA device 0
2. Calls cudaDeviceGetMemPool() for stream-ordered allocations
3. CC-mode driver returns: "operation not supported"
4. sp1-gpu-server panics at task.rs:192 — CudaRustError
5. SP1 SDK reports: "Could not connect to sp1-gpu-server socket"
```

There is no workaround from the application side. Options:

1. **CPU prover** (`SP1_PROVER=cpu`) — ~7 min on 24 vCPU, ~16 min on 8-core arm64
2. **SP1 Network Prover** (`SP1_PROVER=network`) — remote GPU, needs `NETWORK_PRIVATE_KEY` + funded account
3. Non-CC GPU node (if the infrastructure offers one)
4. Wait for SP1 to add CC-mode fallback

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
              count: 1
              capabilities: [gpu]
```

dstack's Docker `daemon.json` registers the nvidia runtime but does NOT set it as default. Without explicit `runtime: nvidia` in compose, the container gets no GPU — silently.

### Proxy Timeout

Phala's reverse proxy has a ~7 minute connection timeout. Any synchronous HTTP request that takes longer will be killed. This is why proof generation uses an async job queue:

1. `?prove=true` → HTTP 202 Accepted with `{ "job_id": "...", "poll_url": "/prove/<id>" }`
2. Background worker processes the job (~7 min)
3. Client polls `GET /prove/{job_id}` for status

### dstack Socket for TEE Attestation

TDX quote generation requires the dstack Unix socket:

```yaml
volumes:
  - /var/run/dstack.sock:/var/run/dstack.sock
environment:
  DSTACK_SOCKET: /var/run/dstack.sock
```

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
2. **Are CUDA libs mounted?** `ls /usr/lib64/libcuda*` and `ls /usr/lib/x86_64-linux-gnu/libcuda*` — if missing, the image lacks the mount-point directories
3. **Can sp1-gpu-server start?** Run it manually with `--help` — if "not found", check autoPatchelfHook
4. **Does CUDA init work?** Run sp1-gpu-server and check stderr — if "operation not supported", you're on a CC-mode GPU
5. **Is CUDA_VISIBLE_DEVICES set correctly?** Must be a single number like `0`
