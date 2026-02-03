use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, Insertable)]
#[diesel(table_name = crate::schema::app_redirect_uris)]
pub struct AppRedirectUri {
    pub id: String,
    pub app_id: String,
    pub redirect_uri: String,
    pub created_at: String,
}
