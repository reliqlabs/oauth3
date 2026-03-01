use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::prove_jobs)]
pub struct ProveJob {
    pub id: String,
    pub status: String,
    pub request_uri: String,
    pub response_body: Vec<u8>,
    pub quote_hex: Option<String>,
    pub proof_json: Option<String>,
    pub error_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
