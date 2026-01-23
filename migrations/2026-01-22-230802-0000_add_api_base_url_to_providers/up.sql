-- Add api_base_url column to oauth_providers table
ALTER TABLE oauth_providers ADD COLUMN api_base_url TEXT;

-- Populate existing providers with default API base URLs
UPDATE oauth_providers SET api_base_url = 'https://www.googleapis.com' WHERE id = 'google';
UPDATE oauth_providers SET api_base_url = 'https://api.github.com' WHERE id = 'github';
-- Dex will use issuer URL, can be set dynamically or left NULL
