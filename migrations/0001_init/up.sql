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
  claims TEXT,
  linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(provider_key, subject)
);
