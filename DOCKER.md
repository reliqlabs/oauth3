# Docker Compose Configuration

This project uses multiple Docker Compose files for different environments.

## File Structure

- **`docker-compose.yml`** - Base configuration (app + database)
- **`docker-compose.override.yml`** - Local development overrides (auto-loaded)
- **`docker-compose.prod.yml`** - Production configuration for Phala TEE

## Local Development

Start with simulator and Dex for local testing:

```bash
# Automatically uses docker-compose.yml + docker-compose.override.yml
docker-compose --profile dev up

# Or explicitly:
docker-compose --profile dev up -d
```

This includes:
- PostgreSQL database
- OAuth3 app
- Phala dstack simulator (for TEE attestation testing)
- Dex OIDC provider (for OAuth testing)

## Production / Phala Deployment

For production deployment (without simulator/dex), you have two options:

### Option 1: Disable Override File (Recommended)

```bash
# Temporarily disable dev overrides
mv docker-compose.override.yml docker-compose.override.yml.disabled

# Build and run production
docker-compose build
docker-compose up

# Re-enable for development
mv docker-compose.override.yml.disabled docker-compose.override.yml
```

### Option 2: Explicit File Selection

```bash
# Use explicit file list (skips auto-loading override.yml)
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up

# Build
docker-compose -f docker-compose.yml -f docker-compose.prod.yml build
```

This includes:
- PostgreSQL database
- OAuth3 app
- Real TEE environment (provided by Phala infrastructure)

**Important**: The `docker-compose.override.yml` file is automatically loaded by docker-compose. For production/Phala builds, make sure to either rename it or use explicit `-f` flags.

## Services

### Always Included
- **db** - PostgreSQL 16 database
- **app** - OAuth3 application

### Development Only (profile: dev)
- **simulator** - Phala dstack simulator for local TEE testing
- **dex** - Dex OIDC provider for local OAuth testing

## Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
# Edit .env with your configuration
```

Required for production:
- `DATABASE_URL` - Postgres connection string
- `APP_PUBLIC_URL` - Public URL of the app
- `COOKIE_KEY_BASE64` - Base64-encoded 64-byte key
- Provider credentials (GOOGLE_CLIENT_ID, GITHUB_CLIENT_ID, etc.)

## Profiles

Use `--profile dev` to enable development services:

```bash
# Development with all services
docker-compose --profile dev up

# Production - only core services
docker-compose up
```

## Testing

Run integration tests against the Docker environment:

```bash
# Start dev environment
docker-compose --profile dev up -d

# Run tests
cargo test --test proxy_endpoint -- --ignored
cargo test --test oidc_dex_docker -- --ignored
```
