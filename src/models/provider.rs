use serde::{Deserialize, Serialize};
use diesel::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::oauth_providers)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    pub mode: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub issuer: Option<String>,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub redirect_path: String,
    pub is_enabled: i32,
    pub created_at: String,
    pub updated_at: String,
}
