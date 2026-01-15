use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::models::user::User;

#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::user_identities)]
#[diesel(belongs_to(User))]
pub struct UserIdentity {
    pub id: String,
    pub user_id: String,
    pub provider_key: String,
    pub subject: String,
    pub email: Option<String>,
    pub claims: Option<String>,
    pub linked_at: String,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::user_identities)]
pub struct NewIdentity<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub provider_key: &'a str,
    pub subject: &'a str,
    pub email: Option<&'a str>,
    pub claims: Option<&'a str>,
}
