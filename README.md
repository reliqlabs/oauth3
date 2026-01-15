### oauth3 — Axum + Diesel (async) SSO starter

Minimal Rust web server that uses Axum on Tokio, Diesel for persistence (async via `diesel-async` on Postgres; SQLite via a blocking adapter), and cookie-based sessions. Authentication is SSO-only; Google OIDC is scaffolded and ready to be wired end-to-end.

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

### Run with Docker Compose (App + Postgres) — Recommended for Local Testing
This repository includes a Dockerfile and a docker-compose.yml to run the server alongside a Postgres database.

Prerequisites:
- Docker and Docker Compose

Steps:

1) **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` and set the required values:
   - **Required for live Google OAuth:**
     - `GOOGLE_CLIENT_ID` — from Google Cloud Console OAuth 2.0 credentials
     - `GOOGLE_CLIENT_SECRET` — from Google Cloud Console OAuth 2.0 credentials
   - **Required for persistent sessions:**
     - `COOKIE_KEY_BASE64` — generate with: `head -c 64 /dev/urandom | base64`
   - **Optional:**
     - `AUTH_GOOGLE_MODE=live` — already set in docker-compose.yml (override in .env if needed)

   **Important:** Configure your Google OAuth 2.0 Client redirect URI as:
   ```
   http://localhost:8080/auth/callback/google
   ```
   in the Google Cloud Console (APIs & Services → Credentials → OAuth 2.0 Client IDs).

2) **Build and start the stack:**
   ```bash
   docker-compose build
   docker-compose up
   ```

   This starts:
   - `db`: Postgres 16 exposed on localhost:5432
   - `app`: the oauth3 server exposed on localhost:8080

   **Database migrations run automatically on app startup** — no manual migration step needed.

3) **Visit the app:**
   ```
   http://localhost:8080/login
   ```

   Click "Continue with Google" to test the OAuth flow.

4) **View logs:**
   ```bash
   docker-compose logs -f app
   ```

5) **Run migrations manually (if needed):**
   The diesel CLI is available inside the container:
   ```bash
   docker-compose exec app diesel migration run
   ```

**Stopping the stack:**
```bash
docker-compose down          # Stop and remove containers
docker-compose down -v       # Also remove the database volume (fresh start)
```

**Rebuilding after code changes:**
```bash
docker-compose build --no-cache app   # Force rebuild without cache
docker-compose up
```

Notes:
- The app container is built with the `pg` feature enabled and includes `libpq` and `diesel` CLI.
- The app reads configuration from `.env` (via `env_file` in docker-compose.yml) and environment variables set in `docker-compose.yml`. Variables in the `environment` section override those from `.env`.
- Migrations are executed automatically on startup via embedded migrations in the binary.
- Sessions require a persistent `COOKIE_KEY_BASE64`; otherwise, cookies are invalidated on restart.
- The Docker build uses layer caching to speed up rebuilds when only source code changes.

---

### Configuration (.env)
The application reads configuration from environment variables (flat) and maps them to structured config.

Required/important variables:
- `DATABASE_URL` — `sqlite://dev.db` or Postgres DSN like `postgres://user:pass@host:5432/db`
- `APP_BIND_ADDR` — default `127.0.0.1:8080`
- `APP_PUBLIC_URL` — default `http://127.0.0.1:8080`
- `COOKIE_KEY_BASE64` — base64-encoded 32 or 64 bytes; if 32B, it will be duplicated to 64B. If unset, a random 64B dev key is generated each run.
- `APP_FORCE_SECURE` — `true|false` to force `Secure` cookie (defaults to false for local)

OIDC placeholders (wired later):
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_ISSUER` (default `https://accounts.google.com`)
- `AUTH_GOOGLE_MODE` — `placeholder` (default) or `live`. Keep `placeholder` until you are ready to test with real Google.

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
- `GET /healthz` — liveness probe
- `GET /login` — simple login page
- `GET /auth/:provider` — start SSO flow (supports `google` placeholder)
- `GET /auth/callback/:provider` — provider callback (placeholder creates a dev session)
- `GET /me` — returns `{ user_id }` from session when logged in
- `POST /logout` — clears session
- `GET /static/*` — static assets

---

### Development tips
- Default cargo feature is `sqlite`. Use `--no-default-features --features pg` for Postgres.
- Logs are controlled by `RUST_LOG`, e.g. `RUST_LOG=info,oauth3=debug`.
- The OIDC flow will require real credentials and redirect URIs configured with the provider.

Troubleshooting builds with Postgres:
- Error like `ld: library 'pq' not found` on macOS means libpq isn’t installed or discoverable. See the libpq installation section above.

---

### Roadmap (short)
- Implement Google OIDC end-to-end: discovery, state/nonce/PKCE, token exchange, ID token verification, repo integration
- Account linking endpoints and GitHub OAuth2
- Tests: unit + integration with mocked providers

---

### Notes about Google OIDC testing
- For now, the app runs in placeholder mode and does not make outbound calls to Google.
- To later enable live testing:
  - Set `AUTH_GOOGLE_MODE=live` in `.env`.
  - Ensure `APP_PUBLIC_URL` matches the origin and the redirect URI `APP_PUBLIC_URL/auth/callback/google` is configured in the Google Cloud console for your OAuth 2.0 Client.
  - Provide valid `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_ISSUER`.
  - Then restart the server. Handlers will switch to the live OIDC flow.
