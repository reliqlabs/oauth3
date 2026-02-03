use async_trait::async_trait;
use crate::models::{
    identity::{NewIdentity, UserIdentity},
    user::{NewUser, User},
    provider::Provider,
    api_key::ApiKey,
    application::Application,
    app_redirect_uri::AppRedirectUri,
    consent::UserConsent,
    oauth_code::OAuthCode,
    app_token::{AppAccessToken, AppRefreshToken},
};

#[async_trait]
pub trait AccountsRepo: Send + Sync {
    async fn find_user_by_identity(&self, provider: &str, subject: &str) -> anyhow::Result<Option<User>>;
    async fn create_user_and_link(&self, new_user: NewUser<'_>, new_identity: NewIdentity<'_>) -> anyhow::Result<User>;
    async fn list_identities(&self, user_id: &str) -> anyhow::Result<Vec<UserIdentity>>;
    async fn list_identities_by_subject(&self, provider_key: &str, subject: &str) -> anyhow::Result<Option<UserIdentity>>;
    async fn get_user_identity(&self, user_id: &str, provider_key: &str) -> anyhow::Result<Option<UserIdentity>>;
    async fn link_identity(&self, new_identity: NewIdentity<'_>) -> anyhow::Result<()>;
    async fn update_identity_tokens(&self, provider_key: &str, subject: &str, access_token: &str, refresh_token: Option<&str>, expires_at: Option<&str>, scopes: Option<&str>) -> anyhow::Result<()>;
    async fn unlink_identity_by_provider(&self, user_id: &str, provider_key: &str) -> anyhow::Result<usize>;
    async fn count_identities(&self, user_id: &str) -> anyhow::Result<i64>;

    // Provider operations
    async fn list_providers(&self) -> anyhow::Result<Vec<Provider>>;
    async fn get_provider(&self, id: &str) -> anyhow::Result<Option<Provider>>;
    async fn save_provider(&self, provider: Provider) -> anyhow::Result<()>;

    // API Key operations
    async fn create_api_key(&self, api_key: ApiKey) -> anyhow::Result<()>;
    async fn list_api_keys(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>>;
    async fn get_api_key_by_hash(&self, key_hash: &str) -> anyhow::Result<Option<ApiKey>>;
    async fn update_api_key_last_used(&self, id: &str) -> anyhow::Result<()>;
    async fn soft_delete_api_key(&self, id: &str, user_id: &str) -> anyhow::Result<()>;

    // Application operations
    async fn list_applications(&self, owner_user_id: &str) -> anyhow::Result<Vec<Application>>;
    async fn get_application(&self, id: &str) -> anyhow::Result<Option<Application>>;
    async fn save_application(&self, app: Application) -> anyhow::Result<()>;

    // Redirect URI operations
    async fn list_app_redirect_uris(&self, app_id: &str) -> anyhow::Result<Vec<AppRedirectUri>>;
    async fn add_app_redirect_uri(&self, redirect_uri: AppRedirectUri) -> anyhow::Result<()>;
    async fn remove_app_redirect_uri(&self, app_id: &str, redirect_uri: &str) -> anyhow::Result<usize>;

    // Consent operations
    async fn get_user_consent(&self, user_id: &str, app_id: &str) -> anyhow::Result<Option<UserConsent>>;
    async fn list_user_consents(&self, user_id: &str) -> anyhow::Result<Vec<UserConsent>>;
    async fn save_user_consent(&self, consent: UserConsent) -> anyhow::Result<()>;
    async fn revoke_user_consent(&self, user_id: &str, app_id: &str) -> anyhow::Result<()>;

    // OAuth authorization codes
    async fn create_oauth_code(&self, code: OAuthCode) -> anyhow::Result<()>;
    async fn consume_oauth_code(&self, code_hash: &str) -> anyhow::Result<Option<OAuthCode>>;

    // App access tokens
    async fn create_app_access_token(&self, token: AppAccessToken) -> anyhow::Result<()>;
    async fn get_app_access_token_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<AppAccessToken>>;
    async fn update_app_access_token_last_used(&self, id: &str) -> anyhow::Result<()>;
    async fn revoke_app_access_token(&self, id: &str) -> anyhow::Result<()>;

    // App refresh tokens
    async fn create_app_refresh_token(&self, token: AppRefreshToken) -> anyhow::Result<()>;
    async fn get_app_refresh_token_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<AppRefreshToken>>;
    async fn revoke_app_refresh_token(&self, id: &str, replaced_by_id: Option<&str>) -> anyhow::Result<()>;
}

#[cfg(feature = "pg")]
pub mod pg;
#[cfg(feature = "sqlite")]
pub mod sqlite;
