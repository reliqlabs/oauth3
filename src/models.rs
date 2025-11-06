use crate::schema::{users, oauth_providers, user_identities};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Queryable, Identifiable, Debug, Serialize, Clone)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub email: Option<String>,
    pub name: Option<String>,
    pub oauth_provider: Option<String>,
    pub oauth_subject: Option<String>,
    pub password_hash: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Debug, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
    pub oauth_provider: Option<&'a str>,
    pub oauth_subject: Option<&'a str>,
    pub password_hash: Option<&'a str>,
}

#[derive(AsChangeset, Debug)]
#[diesel(table_name = users)]
pub struct UpdateUser<'a> {
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
    pub oauth_provider: Option<&'a str>,
    pub oauth_subject: Option<&'a str>,
    pub password_hash: Option<&'a str>,
}

#[derive(Queryable, Identifiable, Debug, Serialize, Clone)]
#[diesel(table_name = oauth_providers)]
pub struct OauthProvider {
    pub id: i32,
    pub key: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub scopes: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Queryable, Identifiable, Associations, Debug, Serialize, Clone)]
#[diesel(table_name = user_identities)]
#[diesel(belongs_to(User, foreign_key = user_id))]
pub struct UserIdentity {
    pub id: i32,
    pub user_id: i32,
    pub provider_key: String,
    pub subject: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Debug, Deserialize)]
#[diesel(table_name = user_identities)]
pub struct NewUserIdentity<'a> {
    pub user_id: i32,
    pub provider_key: &'a str,
    pub subject: &'a str,
}
