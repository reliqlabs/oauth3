-- Create user_identities table to allow multiple OAuth providers per user
CREATE TABLE IF NOT EXISTS user_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider_key TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Ensure a provider+subject is linked to at most one user
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_identities_provider_subject
ON user_identities(provider_key, subject);

-- Helpful index for user lookups
CREATE INDEX IF NOT EXISTS idx_user_identities_user_id
ON user_identities(user_id);

-- Backfill identities from legacy columns on users
INSERT INTO user_identities (user_id, provider_key, subject, created_at, updated_at)
SELECT id, oauth_provider, oauth_subject, created_at, updated_at
FROM users
WHERE oauth_provider IS NOT NULL AND oauth_subject IS NOT NULL;
