# Deployment to Phala

This document describes how to deploy OAuth3 to Phala's TEE infrastructure.

## Deployment Options

### Option 1: Phala Cloud (Recommended)

Phala Cloud provides a managed TEE environment without requiring your own infrastructure.

#### Prerequisites
- Phala Cloud account
- Docker image built and pushed to a registry

#### Steps

1. **Prepare the production build**

```bash
# Disable dev overrides
mv docker-compose.override.yml docker-compose.override.yml.disabled

# Build and tag the image
docker-compose build
docker tag oauth3-app your-registry/oauth3:latest
docker push your-registry/oauth3:latest
```

2. **Update docker-compose.yml for registry image**

Replace the `build` section with your pushed image:

```yaml
services:
  app:
    image: your-registry/oauth3:latest
    # ... rest of config
```

3. **Deploy using Phala Cloud CLI**

```bash
# Install Phala Cloud CLI
npm install -g @phala/cloud-cli

# Login to Phala Cloud
phala login

# Create a CVM (Confidential Virtual Machine)
phala cvms create \
  --name oauth3-prod \
  --compose ./docker-compose.yml \
  --vcpu 2 \
  --memory 4096 \
  --diskSize 60 \
  --teepod-id <your-teepod-id> \
  --image dstack-dev-0.3.5 \
  --env-file ./.env
```

4. **Configure environment variables**

Ensure your `.env` file contains production values:

```bash
DATABASE_URL=postgres://user:pass@db:5432/oauth3
APP_PUBLIC_URL=https://your-domain.com
COOKIE_KEY_BASE64=<your-64-byte-base64-key>
RUST_LOG=info,oauth3=info

# Provider credentials
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

5. **Verify deployment**

```bash
# Check CVM status
phala cvms list

# View logs
phala cvms logs oauth3-prod
```

### Option 2: Self-Hosted dstack

For running on your own TDX infrastructure:

#### Prerequisites
- TDX-enabled server (Intel 4th/5th gen Xeon)
- Ubuntu 22.04 or later
- 16GB+ RAM, 100GB+ disk
- Public IPv4 address

#### Installation

1. **Install dependencies**

```bash
sudo apt install -y build-essential chrpath diffstat lz4 wireguard-tools xorriso
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. **Clone and build dstack**

```bash
git clone https://github.com/Dstack-TEE/meta-dstack.git --recursive
cd meta-dstack/
mkdir build
cd build
../build.sh hostcfg
```

3. **Configure build-config.sh** with your settings

4. **Download guest image**

```bash
../build.sh dl 0.5.2
```

5. **Start dstack components**

In separate terminals:

```bash
# Terminal 1: KMS
./dstack-kms -c kms.toml

# Terminal 2: Gateway (requires sudo)
sudo ./dstack-gateway -c gateway.toml

# Terminal 3: VMM
./dstack-vmm -c vmm.toml
```

6. **Deploy via web interface**

Open `http://localhost:9080` and upload your `docker-compose.yml`

## Production Checklist

Before deploying:

- [ ] Build and push Docker image to registry
- [ ] Update docker-compose.yml to use registry image (not `build:`)
- [ ] Disable or remove `docker-compose.override.yml`
- [ ] Set production environment variables in `.env`
- [ ] Remove `profiles: ["dev"]` services (simulator, dex)
- [ ] Configure provider OAuth credentials (Google, GitHub, etc.)
- [ ] Set up database backups
- [ ] Configure domain and SSL/TLS
- [ ] Test attestation endpoint works in TEE

## File Structure for Deployment

Only these files are needed:

```
oauth3/
├── docker-compose.yml          # Base config (app + db only)
├── docker-compose.prod.yml     # Production overrides
├── .env                        # Production environment variables
└── migrations/                 # Database migrations
```

**Excluded from deployment:**
- `docker-compose.override.yml` (dev only)
- `dex-config.yaml` (dev only)
- `tests/` (dev only)
- `Dockerfile.nix` (build artifact)

## Attestation

Once deployed in TEE, test attestation:

```bash
curl 'https://your-domain.com/proxy/google/oauth2/v2/userinfo?attest=true' \
  -H 'Authorization: Bearer oak_YOUR_API_KEY'
```

The response will include TEE attestation quote and event log proving execution in a trusted environment.

## Monitoring

```bash
# Phala Cloud
phala cvms logs oauth3-prod --follow

# Self-hosted
docker-compose logs -f app
```

## Updating

```bash
# Build new image
docker build -t your-registry/oauth3:v2 .
docker push your-registry/oauth3:v2

# Update deployment
phala cvms update oauth3-prod --image your-registry/oauth3:v2
```

## Support

- Phala Cloud: https://cloud.phala.com
- dstack GitHub: https://github.com/Dstack-TEE/dstack
- Documentation: https://docs.phala.com/dstack
