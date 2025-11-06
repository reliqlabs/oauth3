# oauth3

A minimal Rust web API using Axum + Diesel (SQLite) with initial features:
- Create accounts (email + password)
- Login via SSO/OAuth2 (generic provider config)

This is a starter service to build upon.

## Tech
- Axum 0.8 HTTP server
- Diesel 2 ORM with SQLite and r2d2 pool
- Embedded Diesel migrations
- oauth2 crate for SSO (Authorization Code + PKCE)
- Argon2 password hashing
- JWT access tokens

## Endpoints
- GET /health → { "status": "ok" }
- POST /api/register → { id, email, name }
  - body: { "email": "you@example.com", "name": "You", "password": "secret" }
- GET /auth/login/:provider → redirects to the OAuth2 provider authorization page using the provider config stored in DB (e.g., /auth/login/github)
- GET /auth/callback?code=...&state=... → returns { token, user_id, email, name }

Note: For brevity, there is currently no local password login endpoint. SSO/OAuth2 login is provided. You can add local login later by verifying the password and issuing a JWT using the included helpers.

## Setup
1. Install Rust (stable) and SQLite.
2. Copy environment template and edit values:
   ```bash
   cp .env.example .env
   # edit .env
   ```
3. Build and run:
   ```bash
   cargo run
   ```

The service will create the SQLite database file and run embedded migrations on startup.

## OAuth2 configuration
Multiple OAuth2 providers are now configured in the database (not via env).

On first run the service will create the SQLite DB and run migrations, including the `oauth_providers` table.

Insert one or more providers like so (replace values accordingly):

SQLite example:
```sql
INSERT INTO oauth_providers
    (key, auth_url, token_url, userinfo_url, client_id, client_secret, redirect_url, scopes)
VALUES
    ('github',
     'https://github.com/login/oauth/authorize',
     'https://github.com/login/oauth/access_token',
     'https://api.github.com/user',
     'YOUR_CLIENT_ID',
     'YOUR_CLIENT_SECRET',
     'http://localhost:8080/auth/callback',
     'read:user,user:email');

-- Auth0 example
INSERT INTO oauth_providers
    (key, auth_url, token_url, userinfo_url, client_id, client_secret, redirect_url, scopes)
VALUES
    ('auth0',
     'https://YOUR_DOMAIN/authorize',
     'https://YOUR_DOMAIN/oauth/token',
     'https://YOUR_DOMAIN/userinfo',
     'YOUR_CLIENT_ID',
     'YOUR_CLIENT_SECRET',
     'http://localhost:8080/auth/callback',
     'openid,profile,email');
```

Notes:
- `key` is the short identifier you will use in the login URL, e.g., `/auth/login/github`.
- `userinfo_url` must return JSON with at least `sub` or `id`. If present, `email` and `name` will be stored.
- `scopes` is a comma-separated list.

## Example flows
- Register a local account:
  ```bash
  curl -sS -X POST http://localhost:8080/api/register \
    -H 'content-type: application/json' \
    -d '{"email":"you@example.com","name":"You","password":"Secret123!"}' | jq
  ```

- Start OAuth2 login in a browser:
  - Open http://localhost:8080/auth/login/<provider-key> (e.g., http://localhost:8080/auth/login/github)
  - After consent, you will be redirected back to /auth/callback, which will respond with a JSON token payload.

## Notes
- CORS is permissive by default (allow all). Tighten for production.
- JWT tokens are signed with `JWT_SECRET`. Replace in production.
- For a production deployment, use HTTPS, secure cookie/session if added later, and rotate secrets periodically.
- Add rate limiting and validation as you expand functionality.
