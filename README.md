# oauth3 — OAuth Proxy with TEE Attestation

Rust web service that provides OAuth/OIDC authentication and proxies authenticated requests to provider APIs (Google, GitHub, etc.) with optional TEE (Trusted Execution Environment) attestation. Built with Axum, Diesel (async Postgres/blocking SQLite), and designed for deployment on Phala Cloud's TDX infrastructure.

## Key Features

- **OAuth Proxy** - Authenticated proxy to provider APIs (Google, GitHub, etc.)
- **TEE Attestation** - Optional TDX attestation for requests in trusted execution environments
- **Multi-Provider SSO** - Google OIDC, GitHub OAuth2, Dex (local testing)
- **OAuth App Grants** - Authorization code + PKCE flows for third-party apps, with scoped proxy access
- **API Key Authentication** - Bearer token support for external apps (scope-limited, soft-delete)
- **Account Management** - Link/unlink OAuth providers, manage API keys
- **Reproducible Builds** - Nix-based builds for TEE verification
- **Dual Database Support** - Async Postgres (production) or blocking SQLite (dev)

## Documentation

- **[TEE Attestation](docs/attestation.md)** - Phala Cloud TDX attestation integration
- **[OAuth Applications](docs/oauth-apps.md)** - App registration, consent, and proxy scopes
- **[Reproducible Builds](docs/nix-builds.md)** - Nix-based reproducible builds
- **[Deployment](DEPLOYMENT.md)** - Phala Cloud and self-hosted deployment

## Stack
- Runtime: Tokio
- Web: Axum 0.8, tower-http, tower-cookies
- DB: Diesel 2.x + diesel-async (Postgres) / r2d2 (SQLite)
- Auth: openidconnect, oauth2
- Attestation: dstack (Phala TEE)
- Build: Nix flakes + crane

---

### Quickstart (SQLite, default)
Prerequisites: Rust toolchain, Diesel CLI with SQLite, and this repo.

1) Install Diesel CLI (once):
```
cargo install diesel_cli --no-default-features --features sqlite
```

2) Configure env (copy `.env.example` to `.env` and adjust if needed):
```
cp .env.example .env
```

3) Initialize DB and run migrations:
```
set -a; source .env; set +a
diesel setup
diesel migration run
```

4) Run the server (SQLite is the default cargo feature):
```
cargo run
```

Visit http://127.0.0.1:8080/login

Notes:
- If `COOKIE_KEY_BASE64` is not set, the app will generate a random dev key on startup; sessions will be invalid after restart.
- `/auth/google` and its callback are placeholders until OIDC is fully wired.

---

### Quickstart (Postgres, fully async Diesel)
1) Start Postgres (example Docker):
```
docker run --rm -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=oauth3 -p 5432:5432 postgres:16
```

2) Use a Postgres `DATABASE_URL` in your `.env`:
```
DATABASE_URL=postgres://postgres:postgres@localhost:5432/oauth3
```

3) Install libpq (required for Diesel Postgres builds)

The native Postgres client library (libpq) must be available on your system for builds with the `pg` feature.

- macOS (Homebrew):
  - `brew install libpq`
  - Ensure headers and libs are discoverable by your toolchain (recommended shell exports):
    - `export LDFLAGS="-L$(brew --prefix libpq)/lib"`
    - `export CPPFLAGS="-I$(brew --prefix libpq)/include"`
    - `export PATH="$(brew --prefix libpq)/bin:$PATH"`
  - You can add these to your shell profile (e.g., `~/.zshrc`) so they persist.

- Ubuntu/Debian:
  - `sudo apt-get update && sudo apt-get install -y libpq-dev`

- Fedora/CentOS/RHEL:
  - `sudo dnf install -y postgresql-devel` (or `postgresql-libs` on some versions)

- Windows:
  - Install PostgreSQL and ensure its `bin/` and `lib/` directories are on PATH/LIB. Alternatively, use MSYS2 and install `mingw-w64-<triplet>-postgresql`.

If you prefer not to install a system libpq, let us know — we can add an optional vendored build via `pq-sys` that compiles libpq from source.

4) Install Diesel CLI for Postgres and run migrations:
```
cargo install diesel_cli --no-default-features --features postgres
diesel setup
diesel migration run
```

5) Build and run with the `pg` feature:
```
cargo run --no-default-features --features pg
```

---

### Run with Docker Compose (Full Stack) — Recommended for Local Testing

The compose stack includes:
- **Postgres** database
- **Dex** (local OIDC provider for testing)
- **Phala simulator** (TEE attestation testing)
- **oauth3** app (built with Nix for reproducibility)

**Prerequisites:**
- Docker and Docker Compose
- Nix with flakes (see [docs/nix-builds.md](docs/nix-builds.md))

**Steps:**

1) **Build the Docker image:**
   ```bash
   # Option A: Use Dockerfile.nix (works on macOS)
   docker build -f Dockerfile.nix -t oauth3:nix .

   # Option B: Use pure Nix (Linux only)
   nix build .#dockerImage && docker load < result
   ```

2) **Configure environment:**
   ```bash
   cp .env.example .env
   ```

   For local testing with Dex (no external OAuth setup needed):
   - `COOKIE_KEY_BASE64` — generate with: `head -c 64 /dev/urandom | base64`
   - Dex credentials are pre-configured in `.env.example`

   For live Google/GitHub OAuth (optional):
   - Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `AUTH_GOOGLE_MODE=live`
   - Set `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `AUTH_GITHUB_MODE=live`
   - Configure redirect URIs in provider consoles:
     - Google: `http://localhost:8080/auth/callback/google`
     - GitHub: `http://localhost:8080/auth/callback/github`

3) **Start the stack:**
   ```bash
   docker compose up
   ```

   Services running:
   - `db`: Postgres at `localhost:5432`
   - `dex`: OIDC provider at `localhost:5556`
   - `simulator`: TEE attestation at `localhost:8090`
   - `app`: oauth3 server at `localhost:8080`

4) **Test the app:**
   ```
   http://localhost:8080/login
   ```

   - **Dex (local)**: No setup required, click "Continue with Dex"
   - **Google/GitHub**: Requires credentials in `.env` and `AUTH_*_MODE=live`

5) **Test TEE attestation:**
   ```bash
   curl http://localhost:8080/info
   curl http://localhost:8080/attestation
   ```

**Stopping:**
```bash
docker compose down          # Stop containers
docker compose down -v       # Also remove volumes (fresh DB)
```

**Rebuilding after code changes:**
```bash
# Rebuild image
docker build -f Dockerfile.nix -t oauth3:nix .
# Restart stack
docker compose up
```

**Notes:**
- Migrations run automatically on app startup
- Dex provides a local OIDC provider for testing without external OAuth setup
- Sessions require persistent `COOKIE_KEY_BASE64`
- See [docs/attestation.md](docs/attestation.md) for TEE attestation details
- See [docs/nix-builds.md](docs/nix-builds.md) for reproducible build details

---

### Configuration (.env)
The application reads configuration from environment variables (flat) and maps them to structured config.

Required/important variables:
- `DATABASE_URL` — `sqlite://dev.db` or Postgres DSN like `postgres://user:pass@host:5432/db`
- `APP_BIND_ADDR` — default `127.0.0.1:8080`
- `APP_PUBLIC_URL` — default `http://127.0.0.1:8080`
- `COOKIE_KEY_BASE64` — base64-encoded 32 or 64 bytes; if 32B, it will be duplicated to 64B. If unset, a random 64B dev key is generated each run.
- `APP_FORCE_SECURE` — `true|false` to force `Secure` cookie (defaults to false for local)

**OAuth/OIDC Providers:**

Dex (local OIDC, pre-configured):
- `DEX_CLIENT_ID`, `DEX_CLIENT_SECRET`, `DEX_ISSUER`
- `AUTH_DEX_MODE` — `placeholder` (default) or `live`

Google OIDC:
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- `GOOGLE_ISSUER` (default `https://accounts.google.com`)
- `GOOGLE_SCOPES` (space-separated)
- `AUTH_GOOGLE_MODE` — `placeholder` (default) or `live`

GitHub OAuth2:
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
- `GITHUB_SCOPES` (space-separated)
- `AUTH_GITHUB_MODE` — `placeholder` (default) or `live`

Generate a 64-byte key (recommended):
```
head -c 64 /dev/urandom | base64
```

---

### Migrations and schema
- Diesel config is in `diesel.toml` and migrations are under `migrations/`.
- For development, you can regenerate `src/schema.rs` via:
```
diesel print-schema > src/schema.rs
```

SQLite note: The app also attempts to run pending migrations on startup when built with the `sqlite` feature.

---

### Routes

**OAuth Proxy:**
- `ANY /proxy/{provider}/{path}` — Authenticated proxy to provider APIs
  - Requires session cookie or `Authorization: Bearer <api_key>` header
  - Optional `?attest=true` for TEE attestation
  - Examples:
    - `GET /proxy/google/oauth2/v2/userinfo`
    - `GET /proxy/google/calendar/v3/calendars/primary/events`
    - `GET /proxy/github/user`

**Authentication:**
- `GET /` — landing page
- `GET /healthz` — liveness probe
- `GET /login` — login page with provider options
- `GET /account` — account management (link providers, API keys)
- `GET /auth/{provider}` — start OAuth flow (google, github, dex)
- `GET /auth/callback/{provider}` — OAuth callback
- `GET /me` — current user info from session
- `POST /logout` — clear session

**Account Management:**
- `GET /account/linked-identities` — list linked OAuth providers
- `POST /account/link/{provider}` — link additional provider
- `POST /account/unlink/{provider}` — unlink provider
- `GET /providers` — list available OAuth providers

**API Keys:**
- `GET /account/api-keys` — list user's API keys
- `POST /account/api-keys` — create new API key
- `DELETE /account/api-keys/{key_id}` — soft-delete API key

**TEE Attestation** (see [docs/attestation.md](docs/attestation.md)):
- `GET /info` — application version and build info
- `GET /attestation` — TDX attestation quote

**Static Assets:**
- `GET /static/*` — CSS, JS, images

---

### API Key Authentication

For external applications (non-browser), use API keys instead of session cookies:

**Creating API Keys:**

1. Log in via browser and visit `/account`
2. Create a new API key (copy it immediately - shown only once)
3. Use in external apps with `Authorization: Bearer oak_...` header

**Example Usage:**

```bash
# Using curl
curl https://your-domain.com/proxy/google/oauth2/v2/userinfo \
  -H 'Authorization: Bearer oak_YOUR_API_KEY_HERE'

# With attestation
curl 'https://your-domain.com/proxy/google/oauth2/v2/userinfo?attest=true' \
  -H 'Authorization: Bearer oak_YOUR_API_KEY_HERE'
```

**Security:**
- Keys are hashed (SHA-256) before storage
- Soft-deleted (never reused)
- Scope-limited (proxy only, cannot create new keys)
- Last-used tracking

---

### Deployment

**Local Development:**
```bash
docker compose up  # All services (db, dex, simulator, app)
```

**Phala Cloud:**
```bash
# Configure .env.phala
cp .env.phala.example .env.phala
nano .env.phala

# Build and push image
nix build .#dockerImage
docker load < result
docker tag oauth3:nix ghcr.io/yourname/oauth3:latest
docker push ghcr.io/yourname/oauth3:latest

# Deploy
./phala-deploy.sh .env.phala
```

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for complete instructions.

**GitHub Actions:**

The repository includes a workflow that automatically builds and publishes Docker images to GHCR on push to main or tag creation. Images are built with Nix for reproducibility.

---

### Development Tips

- Default cargo feature is `sqlite`. Use `--no-default-features --features pg` for Postgres
- Logs: `RUST_LOG=info,oauth3=debug`
- OAuth requires real credentials and configured redirect URIs
- Migrations run automatically on startup
- Session persistence requires stable `COOKIE_KEY_BASE64`

**Troubleshooting Postgres builds:**
- `ld: library 'pq' not found` → install libpq (see Quickstart section)

---

### Roadmap

- **Token Refresh**: Automatic token refresh in proxy endpoint
- **Encryption at Rest**: AEAD encryption for stored tokens
- **Background Cleanup**: Periodic cleanup of expired tokens/identities
- **Token Revocation**: Support for provider revocation endpoints
- **Provider UI**: Web interface for managing provider configurations
- **Observability**: Structured logging, metrics, trace IDs

---

### Testing OAuth Providers

**Dex (recommended for local dev):**
- Pre-configured in `.env.example` and `docker-compose.yml`
- No external setup required
- Set `AUTH_DEX_MODE=live` to enable
- Works with `docker compose up`

**Google OIDC:**
- Create OAuth 2.0 Client in [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
- Configure redirect URI: `http://localhost:8080/auth/callback/google`
- Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` in `.env`
- Set `AUTH_GOOGLE_MODE=live`

**GitHub OAuth:**
- Create OAuth App in [GitHub Developer Settings](https://github.com/settings/developers)
- Configure callback URL: `http://localhost:8080/auth/callback/github`
- Set `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` in `.env`
- Set `AUTH_GITHUB_MODE=live`

**Placeholder mode (default):**
- Providers in `placeholder` mode show UI but create mock sessions
- Useful for frontend testing without real OAuth setup
