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
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<String>,
    pub scopes: Option<String>,
    pub claims: Option<String>,
    pub linked_at: String,
}

#[derive(Debug, Clone, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::user_identities)]
pub struct NewIdentity<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub provider_key: &'a str,
    pub subject: &'a str,
    pub email: Option<&'a str>,
    pub access_token: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
    pub expires_at: Option<&'a str>,
    pub scopes: Option<&'a str>,
    pub claims: Option<&'a str>,
}
