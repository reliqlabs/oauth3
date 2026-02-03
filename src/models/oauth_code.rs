use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, Insertable)]
#[diesel(primary_key(code_hash))]
#[diesel(table_name = crate::schema::oauth_codes)]
pub struct OAuthCode {
    pub code_hash: String,
    pub app_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: String,
    pub created_at: String,
    pub consumed_at: Option<String>,
}
