use async_trait::async_trait;
use crate::models::{
    identity::{NewIdentity, UserIdentity},
    user::{NewUser, User},
    provider::Provider,
    api_key::ApiKey,
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
}

#[cfg(feature = "pg")]
pub mod pg;
#[cfg(feature = "sqlite")]
pub mod sqlite;
