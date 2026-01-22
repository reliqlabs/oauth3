# oauth3 — Axum + Diesel (async) SSO starter

Minimal Rust web server that uses Axum on Tokio, Diesel for persistence (async via `diesel-async` on Postgres; SQLite via a blocking adapter), and cookie-based sessions. Authentication is SSO-only; Google OIDC is scaffolded and ready to be wired end-to-end.

## Documentation

- **[TEE Attestation](docs/attestation.md)** - Phala Cloud TDX attestation integration
- **[Reproducible Builds](docs/nix-builds.md)** - Nix-based reproducible builds for TEE verification

#### Features
- Axum 0.8 router, tracing middleware, static file serving
- Diesel schema and migrations (`users`, `user_identities`)
- Async DB layer
  - Postgres: `diesel-async` + `bb8` pool (fully async)
  - SQLite: `r2d2` pool with `spawn_blocking` adapter (temporary until switching to Postgres)
- Cookie sessions with signing + encryption (`tower-cookies`)
- Simple login page with provider links

#### Stack
- Runtime: Tokio
- Web: Axum 0.8, tower-http 0.6, tracing
- DB: Diesel 2.x, diesel-async 0.5 (pg), r2d2 (sqlite)
- Migrations: diesel_migrations + Diesel CLI
- Auth: openidconnect (OIDC), oauth2 (for non-OIDC providers, later)

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

**Authentication:**
- `GET /healthz` — liveness probe
- `GET /login` — simple login page
- `GET /auth/:provider` — start SSO flow (supports `google`, `github`, `dex`)
- `GET /auth/callback/:provider` — provider callback
- `GET /me` — returns `{ user_id }` from session when logged in
- `POST /logout` — clears session
- `GET /static/*` — static assets

**TEE Attestation** (see [docs/attestation.md](docs/attestation.md)):
- `GET /info` — application version and build info
- `GET /attestation` — TDX attestation quote proving code runs in TEE

---

### Development tips
- Default cargo feature is `sqlite`. Use `--no-default-features --features pg` for Postgres.
- Logs are controlled by `RUST_LOG`, e.g. `RUST_LOG=info,oauth3=debug`.
- The OIDC flow will require real credentials and redirect URIs configured with the provider.

Troubleshooting builds with Postgres:
- Error like `ld: library 'pq' not found` on macOS means libpq isn’t installed or discoverable. See the libpq installation section above.

---

### Roadmap
- **Encryption at Rest**: Implement AEAD (e.g., AES-GCM) encryption for `access_token` and `refresh_token` columns.
- **Automated Token Refresh Middleware**: Create an Axum extractor or middleware to automatically refresh tokens before expiry.
- **Background Cleanup**: Implement a background task to periodically clean up expired or revoked tokens/identities.
- **Token Revocation Support**: Add support for OIDC/OAuth2 revocation endpoints during logout or unlinking.
- **Configuration Externalization**: Move provider definitions into an external configuration file or management UI.
- **UI/UX Improvements**: Dynamic login page rendering and improved error feedback.
- **Observability**: Structured logging with trace IDs and authentication metrics.

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
