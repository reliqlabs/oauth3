# OAuth Applications and Proxy Grants

oauth3 supports OAuth 2.1 style authorization code grants for third-party applications. Users can grant proxy access to their linked provider identities, and apps can exchange authorization codes for access and refresh tokens.

## Scopes

Scopes are space-separated strings. The proxy enforces provider-level scope checks.

Supported patterns:
- `proxy` (access to any provider)
- `proxy:{provider}` (access to a specific provider, e.g. `proxy:google`)
- `proxy:{provider}:read` and `proxy:{provider}:write` (reserved for future method/path restrictions)

Provider IDs are lowercase (e.g. `google`, `github`, `dex`).

## Register an application

Use the account UI (`/account`) to create an application and add redirect URIs.

Fields:
- **Client type**: `confidential` (server-side) or `public` (PKCE required).
- **Allowed scopes**: space-separated scope patterns (defaults to `proxy`).

After creation, copy the client secret for confidential apps (it is only shown once).

## Authorization flow

1) Redirect the user to `/oauth/authorize` with standard OAuth parameters:

```
GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=proxy:google&state=...&code_challenge=...&code_challenge_method=S256
```

2) The user approves the consent screen.

3) Exchange the authorization code for tokens:

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=...&
redirect_uri=...&
client_id=...&
client_secret=...&
code_verifier=...
```

Response:

```
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "proxy:google"
}
```

Public clients must send PKCE parameters. Confidential clients must authenticate with `client_secret` (basic auth also works).

## Using access tokens with the proxy

Use the access token as a Bearer token for `/proxy/{provider}/{path}`:

```
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://localhost:8080/proxy/google/userinfo"
```

If the token has `proxy:google`, only Google proxy requests are allowed. Tokens with `proxy` can access any provider.

## Refresh and revoke

Use the refresh token to rotate credentials:

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=...&
client_id=...&
client_secret=...
```

Revoke a refresh token:

```
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=...&
client_id=...&
client_secret=...
```

Revoking user consent from `/account` immediately blocks existing tokens.
