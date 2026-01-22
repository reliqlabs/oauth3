# Reproducible Builds with Nix

This project supports reproducible builds using Nix flakes to ensure bit-for-bit identical binaries.

## Why Reproducible Builds?

For TEE (Trusted Execution Environment) attestation, reproducible builds allow:
- **Verification**: Anyone can rebuild and verify the binary matches the MRTD measurement
- **Transparency**: Source code provably corresponds to running code
- **Trust**: No hidden modifications between source and deployed binary

## Prerequisites

Install Nix with flakes support:
```bash
# Install Nix
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install

# Or on macOS with existing Nix:
nix --version  # should be >= 2.4
```

## Build Methods

### Method Comparison

| Method | Use Case | Platform Support | Build Time | Reproducibility |
|--------|----------|------------------|------------|-----------------|
| **Pure Nix** | Linux CI/production | Linux only | ~15-25 min cold, 2-5 min warm | ✅ Fully reproducible |
| **Dockerfile.nix** | Local dev on macOS | Any (Docker) | ~15-25 min cold, 2-5 min warm | ✅ Fully reproducible |
| **Local binary** | Development/testing | Native platform | Fastest (incremental) | ⚠️  Platform-specific |

### 1. Build Binary Locally (Development)

**Platform:** Native (macOS/Linux)
**Use case:** Local development and testing

```bash
# Build the application for your platform
nix build .#oauth3

# Run it
./result/bin/oauth3

# Or run directly
nix run
```

**Note:** This builds for your native platform (macOS on Mac, Linux on Linux). Not suitable for Docker deployment from macOS.

### 2. Build Docker Image with Pure Nix (Linux Only)

**Platform:** Linux (x86_64-linux or aarch64-linux)
**Use case:** CI/CD pipelines, Linux servers, production builds

```bash
# Build Docker image using Nix (Linux only)
nix build .#dockerImage

# Load into Docker
docker load < result

# Run it
docker run -p 8080:8080 oauth3:nix
```

**Requirements:**
- Must run on Linux (not macOS)
- Or use remote Linux builder
- Or build in Linux Docker container (see Method 3)

**Advantages:**
- Fastest on Linux systems
- Native Nix store caching
- Smallest output artifact

### 3. Build Docker Image with Dockerfile.nix (Recommended for macOS)

**Platform:** Any (macOS, Linux, Windows with Docker)
**Use case:** Local development on macOS, cross-platform builds

```bash
# Build using Nix inside Linux container
docker build -f Dockerfile.nix -t oauth3:nix-docker .

# Run it
docker run -p 8080:8080 oauth3:nix-docker
```

**How it works:**
1. Uses `nixos/nix:2.26.3` Linux container as builder
2. Runs `nix build` inside the container
3. Copies minimal runtime closure to final Debian image
4. Same reproducibility guarantees as pure Nix

**Build time:**
- **Cold build** (no cache): 15-25 minutes
- **Warm build** (deps cached): 2-5 minutes

**Advantages:**
- Works on macOS without cross-compilation
- Produces Linux binaries suitable for Docker
- Same Nix reproducibility guarantees
- Smaller final image (minimal Debian base)

**Trade-offs:**
- Slower than native Linux builds (Docker overhead)
- Larger build-time resource usage (two-stage build)

### 4. Use in docker-compose

Update `docker-compose.yml`:
```yaml
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.nix  # Use Dockerfile.nix for reproducibility
    # ... rest of config
```

Then:
```bash
docker compose up --build
```

## Which Method Should I Use?

### For Local Development (macOS)
→ **Use Dockerfile.nix**
- Works without additional setup
- Fully reproducible
- Can build and test Linux images locally

### For CI/CD on Linux
→ **Use Pure Nix (`nix build .#dockerImage`)**
- Fastest build times
- Best caching behavior
- Direct Nix store integration

### For Quick Testing
→ **Use Local Binary (`nix build .#oauth3`)**
- Fastest iteration cycle
- Good for development
- Not suitable for production

## Reproducibility Guarantees

The Nix build ensures:

1. **Locked Dependencies**: `flake.lock` pins all inputs
2. **Fixed Rust Version**: rust-toolchain.toml specifies exact version
3. **Deterministic Builds**: CARGO_INCREMENTAL=0, fixed timestamps
4. **Isolated Environment**: No host system contamination

## Verifying Reproducibility

Two developers building from the same commit should get identical binaries:

```bash
# Developer A
nix build .#oauth3
sha256sum result/bin/oauth3

# Developer B (same commit)
nix build .#oauth3
sha256sum result/bin/oauth3

# Hashes should match exactly
```

## Development Shell

Enter a development environment with all tools:

```bash
nix develop

# Now you have:
# - Rust toolchain
# - diesel-cli
# - PostgreSQL client
# - rust-analyzer
```

## Updating Dependencies

### Update Rust dependencies
```bash
# Normal Cargo workflow
cargo update
```

### Update Nix flake inputs
```bash
# Update all inputs
nix flake update

# Update specific input
nix flake lock --update-input nixpkgs
```

### Commit the locks
```bash
git add flake.lock Cargo.lock
git commit -m "Update dependencies"
```

## TEE Deployment Workflow

1. **Build locally with Nix**:
   ```bash
   nix build .#oauth3
   sha256sum result/bin/oauth3  # Record this hash
   ```

2. **Generate MRTD**: Deploy to TEE and get attestation quote

3. **Verify MRTD matches**: Extract MRTD from quote, compare to expected hash

4. **Anyone can reproduce**: Others build from same commit, verify hash matches

## Comparison: Build Approaches

| Aspect | Standard Dockerfile | Dockerfile.nix | Pure Nix (Linux) |
|--------|--------------------|-----------------|--------------------|
| Reproducibility | ❌ No | ✅ Yes (bit-for-bit) | ✅ Yes (bit-for-bit) |
| Platform | Any (Docker) | Any (Docker) | Linux only |
| Dependency pinning | Cargo.lock only | Cargo.lock + flake.lock | Cargo.lock + flake.lock |
| Build cache | Docker layers | Nix store in container | Nix store (native) |
| Offline builds | ❌ No | ✅ Yes (with cache) | ✅ Yes (with cache) |
| Cold build time | ~2-3 min | ~15-25 min | ~15-25 min |
| Warm build time | ~2-3 min | ~2-5 min | ~2-5 min |
| macOS support | ✅ Yes | ✅ Yes | ❌ No (requires remote builder) |
| TEE verification | ❌ No | ✅ Yes | ✅ Yes |

## Troubleshooting

### "experimental-features" error
Enable flakes in `/etc/nix/nix.conf`:
```
experimental-features = nix-command flakes
```

### Build fails with linking errors
Ensure libpq is available:
```bash
nix develop
pkg-config --libs libpq
```

### Cannot build on macOS with pure Nix
**Error:** `required system or feature not available: aarch64-linux`

**Solution:** Use Dockerfile.nix instead:
```bash
docker build -f Dockerfile.nix -t oauth3:nix-docker .
```

Or set up a remote Linux builder (advanced).

### Docker image too large
Image sizes:
- **Dockerfile.nix**: ~300-400 MB (minimal Debian + runtime deps)
- **Pure Nix**: ~450 MB (all dependencies in /nix/store)
- **Standard Dockerfile**: ~100-150 MB (minimal Alpine)

For production, consider:
- Using multi-stage builds to minimize runtime dependencies
- Stripping debug symbols
- Using distroless base images

## References

- [Nix Flakes](https://nixos.wiki/wiki/Flakes)
- [Crane - Nix Cargo builds](https://github.com/ipetkov/crane)
- [Reproducible Builds](https://reproducible-builds.org/)
