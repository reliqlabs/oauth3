use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::applications)]
pub struct Application {
    pub id: String,
    pub owner_user_id: String,
    pub name: String,
    pub client_type: String,
    pub client_secret_hash: Option<String>,
    pub allowed_scopes: String,
    pub is_enabled: i32,
    pub created_at: String,
    pub updated_at: String,
}
