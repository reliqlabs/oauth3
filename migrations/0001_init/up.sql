-- Users table
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  primary_email TEXT,
  display_name TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- External identities linked to users
CREATE TABLE user_identities (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_key TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT,
  access_token TEXT,
  refresh_token TEXT,
  expires_at TEXT,
  claims TEXT,
  linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(provider_key, subject)
);

-- OIDC/OAuth2 Providers configuration
CREATE TABLE oauth_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    provider_type TEXT NOT NULL, -- 'oidc' or 'oauth2'
    mode TEXT NOT NULL DEFAULT 'live', -- 'live' or 'placeholder'
    client_id TEXT,
    client_secret TEXT,
    issuer TEXT,
    auth_url TEXT,
    token_url TEXT,
    redirect_path TEXT NOT NULL,
    is_enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
