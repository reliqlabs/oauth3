use async_trait::async_trait;
use crate::models::{
    identity::{NewIdentity, UserIdentity},
    user::{NewUser, User},
};

#[async_trait]
pub trait AccountsRepo: Send + Sync {
    async fn find_user_by_identity(&self, provider: &str, subject: &str) -> anyhow::Result<Option<User>>;
    async fn create_user_and_link(&self, new_user: NewUser<'_>, new_identity: NewIdentity<'_>) -> anyhow::Result<User>;
    async fn list_identities(&self, user_id: &str) -> anyhow::Result<Vec<UserIdentity>>;
    async fn link_identity(&self, new_identity: NewIdentity<'_>) -> anyhow::Result<()>;
    async fn unlink_identity_by_provider(&self, user_id: &str, provider_key: &str) -> anyhow::Result<usize>;
    async fn count_identities(&self, user_id: &str) -> anyhow::Result<i64>;
}

#[cfg(feature = "pg")]
pub mod pg;
#[cfg(feature = "sqlite")]
pub mod sqlite;
