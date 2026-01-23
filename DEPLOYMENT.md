# Deployment to Phala

This document describes how to deploy OAuth3 to Phala's TEE infrastructure.

## Quick Start: Phala Cloud Deployment

### Prerequisites
- Phala Cloud account
- Docker registry (GitHub Container Registry, Docker Hub, etc.)

### Steps

1. **Build and push Docker image**

```bash
# Build production image
docker build -t ghcr.io/yourname/oauth3:latest .

# Push to registry
docker push ghcr.io/yourname/oauth3:latest
```

2. **Configure environment**

```bash
# Copy Phala environment template
cp .env.phala.example .env.phala

# Edit with your values
nano .env.phala
```

**Required variables in `.env.phala`:**
```bash
DOCKER_IMAGE=ghcr.io/yourname/oauth3:latest
POSTGRES_PASSWORD=your-secure-password
COOKIE_KEY_BASE64=$(openssl rand -base64 64)

# APP_PUBLIC_URL - can be set after deployment when you know the URL
# For initial deployment, you can leave this unset or use a placeholder
APP_PUBLIC_URL=https://your-cvm-url.phala.network

# Optional: Enable OAuth providers (requires APP_PUBLIC_URL to be set)
AUTH_GOOGLE_MODE=live
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
```

**Note on APP_PUBLIC_URL:**
- You won't know your public URL until after deployment
- The script will deploy with a placeholder if not set
- After deployment, get your URL from `phala cvms list`
- Update the environment variable with `phala cvms update`
- Configure OAuth callback URLs with providers using the Phala URL

3. **Deploy to Phala Cloud**

```bash
# Install Phala Cloud CLI
npm install -g @phala/cloud-cli

# Login
phala login

# Deploy using the deployment script
./phala-deploy.sh .env.phala
```

The script reads all variables from `.env.phala` and passes them to the `phala cvms create` command. Optional deployment settings (TEEPOD_ID, VCPU, MEMORY, etc.) can be configured in the `.env.phala` file.

4. **Verify deployment**

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

- [ ] **CRITICAL**: Rename `docker-compose.override.yml` to `.disabled`
- [ ] **VERIFY**: Run `docker-compose config --services` shows only `db` and `app`
- [ ] Build and push Docker image to registry
- [ ] Update docker-compose.yml to use registry image (not `build:`)
- [ ] Set production environment variables in `.env`
- [ ] Configure provider OAuth credentials (Google, GitHub, etc.)
- [ ] Set up database backups
- [ ] Configure domain and SSL/TLS
- [ ] Test attestation endpoint works in TEE

### Verification Commands

```bash
# Ensure override is disabled
ls -la docker-compose.override.yml.disabled

# This should output ONLY: db, app
docker-compose config --services

# This should NOT contain "simulator" or "dex"
docker-compose config | grep -E "(simulator|dex)"
```

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
