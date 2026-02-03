use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::user_consents)]
pub struct UserConsent {
    pub id: String,
    pub user_id: String,
    pub app_id: String,
    pub scopes: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}
