use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlite", derive(diesel::Queryable, diesel::Insertable))]
#[cfg_attr(feature = "sqlite", diesel(table_name = crate::schema::api_keys))]
#[cfg_attr(feature = "pg", derive(diesel::Queryable, diesel::Insertable))]
#[cfg_attr(feature = "pg", diesel(table_name = crate::schema::api_keys))]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub key_hash: String,
    pub scopes: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub deleted_at: Option<String>,
}

impl ApiKey {
    /// Check if this key has the required scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.split_whitespace().any(|s| s == scope)
    }

    /// Check if key is deleted (soft delete)
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }
}

/// Scopes for API keys
pub mod scopes {
    pub const PROXY: &str = "proxy";
}
