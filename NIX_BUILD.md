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

### 1. Build Binary Locally

```bash
# Build the application
nix build .#oauth3

# Run it
./result/bin/oauth3

# Or run directly
nix run
```

### 2. Build Docker Image with Nix

Pure Nix approach (fully reproducible):
```bash
# Build Docker image using Nix
nix build .#dockerImage

# Load into Docker
docker load < result

# Run it
docker run -p 8080:8080 oauth3:nix
```

### 3. Build Docker Image with Dockerfile.nix

Hybrid approach (Nix build in Docker):
```bash
# Build using the Nix-enabled Dockerfile
docker build -f Dockerfile.nix -t oauth3:nix-docker .

# Run it
docker run -p 8080:8080 oauth3:nix-docker
```

### 4. Use in docker-compose

Update `docker-compose.yml`:
```yaml
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.nix
    # ... rest of config
```

Then:
```bash
docker compose up --build
```

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

## Comparison: Nix vs Standard Build

| Aspect | Standard Dockerfile | Nix Build |
|--------|-------------------|-----------|
| Reproducibility | No (varies by build time) | Yes (bit-for-bit) |
| Dependency pinning | Cargo.lock only | Cargo.lock + flake.lock |
| Build cache | Docker layers | Nix store |
| Offline builds | Partial | Full (with cache) |
| Build time | ~1-2 min | ~1-2 min (first), seconds (cached) |

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

### Docker image too large
Nix builds layered images efficiently, but if size is critical:
```bash
# Build minimal image
nix build .#dockerImage
docker load < result
docker images oauth3  # Check size
```

## References

- [Nix Flakes](https://nixos.wiki/wiki/Flakes)
- [Crane - Nix Cargo builds](https://github.com/ipetkov/crane)
- [Reproducible Builds](https://reproducible-builds.org/)
