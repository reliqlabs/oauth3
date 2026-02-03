CREATE TABLE applications (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  client_type TEXT NOT NULL,
  client_secret_hash TEXT,
  allowed_scopes TEXT NOT NULL,
  is_enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE app_redirect_uris (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(app_id, redirect_uri)
);

CREATE TABLE user_consents (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT,
  UNIQUE(user_id, app_id)
);

CREATE TABLE oauth_codes (
  code_hash TEXT PRIMARY KEY,
  app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scopes TEXT NOT NULL,
  code_challenge TEXT,
  code_challenge_method TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  consumed_at TEXT
);

CREATE INDEX idx_oauth_codes_app_id ON oauth_codes(app_id);
CREATE INDEX idx_oauth_codes_user_id ON oauth_codes(user_id);
CREATE INDEX idx_oauth_codes_expires_at ON oauth_codes(expires_at);

CREATE TABLE app_access_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE INDEX idx_app_access_tokens_token_hash ON app_access_tokens(token_hash);
CREATE INDEX idx_app_access_tokens_user_id ON app_access_tokens(user_id);
CREATE INDEX idx_app_access_tokens_app_id ON app_access_tokens(app_id);

CREATE TABLE app_refresh_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT,
  rotation_parent_id TEXT,
  replaced_by_id TEXT,
  FOREIGN KEY(rotation_parent_id) REFERENCES app_refresh_tokens(id),
  FOREIGN KEY(replaced_by_id) REFERENCES app_refresh_tokens(id)
);

CREATE INDEX idx_app_refresh_tokens_token_hash ON app_refresh_tokens(token_hash);
CREATE INDEX idx_app_refresh_tokens_user_id ON app_refresh_tokens(user_id);
CREATE INDEX idx_app_refresh_tokens_app_id ON app_refresh_tokens(app_id);
