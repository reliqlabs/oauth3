-- Remove api_base_url column from oauth_providers table
ALTER TABLE oauth_providers DROP COLUMN api_base_url;
