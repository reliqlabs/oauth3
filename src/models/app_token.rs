use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::app_access_tokens)]
pub struct AppAccessToken {
    pub id: String,
    pub token_hash: String,
    pub app_id: String,
    pub user_id: String,
    pub scopes: String,
    pub expires_at: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::app_refresh_tokens)]
pub struct AppRefreshToken {
    pub id: String,
    pub token_hash: String,
    pub app_id: String,
    pub user_id: String,
    pub scopes: String,
    pub expires_at: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub rotation_parent_id: Option<String>,
    pub replaced_by_id: Option<String>,
}
