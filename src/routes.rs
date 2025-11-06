use std::{collections::HashMap, sync::Arc};

use axum::{extract::{State, Query, Path}, Json, response::IntoResponse};
use axum::http::StatusCode;
use axum::response::Redirect;
use diesel::prelude::*;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenUrl, AuthorizationCode, TokenResponse};
use oauth2::reqwest::async_http_client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{config::AppConfig, db::DbPool, models::{User, NewUser, OauthProvider}, schema::users, security::{create_jwt, hash_password}};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub pool: DbPool,
    // map: oauth state -> (provider_key, pkce_verifier)
    pub pkce_store: Arc<RwLock<HashMap<String, (String, PkceCodeVerifier)>>>,
}

impl AppState {
    pub fn new(config: AppConfig, pool: DbPool) -> Self {
        Self { config, pool, pkce_store: Arc::new(RwLock::new(HashMap::new())) }
    }

    fn oauth_client_for(&self, provider: &OauthProvider) -> anyhow::Result<BasicClient> {
        let auth_url = AuthUrl::new(provider.auth_url.clone())?;
        let token_url = TokenUrl::new(provider.token_url.clone())?;
        let redirect = RedirectUrl::new(provider.redirect_url.clone())?;
        let client = BasicClient::new(
            ClientId::new(provider.client_id.clone()),
            Some(ClientSecret::new(provider.client_secret.clone())),
            auth_url,
            Some(token_url),
        ).set_redirect_uri(redirect);
        Ok(client)
    }
}

#[derive(Serialize)]
struct HealthResponse { status: &'static str }

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub name: Option<String>,
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse { pub id: i32, pub email: String, pub name: Option<String> }

pub async fn register(State(state): State<AppState>, Json(body): Json<RegisterRequest>) -> impl IntoResponse {
    let mut conn = match state.pool.get() {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("db pool: {}", e)).into_response(),
    };

    // Check if email already exists
    match users::table.filter(users::email.eq(&body.email)).first::<User>(&mut conn).optional() {
        Ok(Some(_)) => return (StatusCode::CONFLICT, "email already exists").into_response(),
        Ok(None) => {}
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("db query: {}", e)).into_response(),
    }

    let pass_hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("hash error: {}", e)).into_response(),
    };

    let new_user = NewUser {
        email: Some(body.email.as_str()),
        name: body.name.as_deref(),
        oauth_provider: None,
        oauth_subject: None,
        password_hash: Some(pass_hash.as_str()),
    };

    match diesel::insert_into(users::table).values(&new_user).execute(&mut conn) {
        Ok(_) => {}
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("insert error: {}", e)).into_response(),
    }

    let created = match users::table.filter(users::email.eq(&body.email)).first::<User>(&mut conn) {
        Ok(u) => u,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("fetch created: {}", e)).into_response(),
    };

    let resp = RegisterResponse { id: created.id, email: created.email.clone().unwrap_or_default(), name: created.name.clone() };
    (StatusCode::CREATED, Json(resp)).into_response()
}

pub async fn oauth_login(Path(provider_key): Path<String>, State(state): State<AppState>) -> impl IntoResponse {
    // fetch provider from DB
    let provider = {
        let mut conn = match state.pool.get() {
            Ok(c) => c,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("db pool: {}", e)).into_response(),
        };
        use crate::schema::oauth_providers::dsl::*;
        match oauth_providers.filter(key.eq(&provider_key)).first::<OauthProvider>(&mut conn).optional() {
            Ok(Some(p)) => p,
            Ok(None) => return (StatusCode::NOT_FOUND, format!("unknown provider '{}" , provider_key)).into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {}", e)).into_response(),
        }
    };

    let client = match state.oauth_client_for(&provider) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("oauth client: {}", e)).into_response(),
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(provider.scopes.split(',').filter_map(|s| { let t = s.trim(); if t.is_empty() { None } else { Some(Scope::new(t.to_string())) } }))
        .set_pkce_challenge(pkce_challenge)
        .url();

    {
        let mut map = state.pkce_store.write().await;
        map.insert(csrf_token.secret().to_string(), (provider.key.clone(), pkce_verifier));
    }

    Redirect::to(auth_url.as_ref()).into_response()
}

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    code: String,
    state: String,
}

#[derive(Serialize)]
pub struct AuthTokenResponse { token: String, user_id: i32, email: Option<String>, name: Option<String> }

pub async fn oauth_callback(State(state): State<AppState>, Query(query): Query<OAuthCallbackQuery>) -> impl IntoResponse {
    // take PKCE verifier and provider key
    let tuple = {
        let mut map = state.pkce_store.write().await;
        map.remove(&query.state)
    };
    let Some((provider_key, pkce_verifier)) = tuple else {
        return (StatusCode::BAD_REQUEST, "invalid state").into_response();
    };

    // fetch provider from DB
    let provider = {
        let mut conn = match state.pool.get() {
            Ok(c) => c,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("db pool: {}", e)).into_response(),
        };
        use crate::schema::oauth_providers::dsl::*;
        match oauth_providers.filter(key.eq(&provider_key)).first::<OauthProvider>(&mut conn).optional() {
            Ok(Some(p)) => p,
            Ok(None) => return (StatusCode::NOT_FOUND, format!("unknown provider '{}" , provider_key)).into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {}", e)).into_response(),
        }
    };

    let client = match state.oauth_client_for(&provider) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("oauth client: {}", e)).into_response(),
    };

    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await;

    let token = match token_result {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("token exchange: {}", e)).into_response(),
    };

    let access_token = token.access_token().secret();

    // fetch userinfo
    let userinfo_url = provider.userinfo_url.clone();
    let http = reqwest::Client::new();
    let profile_json: serde_json::Value = match http.get(userinfo_url).bearer_auth(access_token).send().await {
        Ok(r) => match r.error_for_status() {
            Ok(ok) => match ok.json().await { Ok(j) => j, Err(e) => return (StatusCode::BAD_GATEWAY, format!("userinfo json: {}", e)).into_response() },
            Err(e) => return (StatusCode::BAD_GATEWAY, format!("userinfo status: {}", e)).into_response(),
        },
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("userinfo request: {}", e)).into_response(),
    };

    // extract identity
    let subject = profile_json.get("sub")
        .or_else(|| profile_json.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let Some(subject) = subject else {
        return (StatusCode::BAD_GATEWAY, "userinfo missing subject").into_response();
    };

    let email_opt = profile_json.get("email").and_then(|v| v.as_str()).map(|s| s.to_string());
    let name_opt = profile_json.get("name").or_else(|| profile_json.get("preferred_username")).and_then(|v| v.as_str()).map(|s| s.to_string());

    // upsert user
    let mut conn = match state.pool.get() {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("db pool: {}", e)).into_response(),
    };

    use crate::schema::users::dsl::*;

    let existing = users
        .filter(oauth_provider.eq(&provider.key))
        .filter(oauth_subject.eq(&subject))
        .first::<User>(&mut conn)
        .optional();

    let user = match existing {
        Ok(Some(u)) => u,
        Ok(None) => {
            let new_user = NewUser {
                email: email_opt.as_deref(),
                name: name_opt.as_deref(),
                oauth_provider: Some(provider.key.as_str()),
                oauth_subject: Some(subject.as_str()),
                password_hash: None,
            };
            match diesel::insert_into(users).values(&new_user).execute(&mut conn) {
                Ok(_) => {}
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("insert user: {}", e)).into_response(),
            }
            match users
                .filter(oauth_provider.eq(&provider.key))
                .filter(oauth_subject.eq(&subject))
                .first::<User>(&mut conn) {
                Ok(u) => u,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("fetch new user: {}", e)).into_response(),
            }
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("query user: {}", e)).into_response(),
    };

    let token = match create_jwt(&format!("user:{}", user.id), &state.config.jwt_secret, 60 * 24) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("jwt: {}", e)).into_response(),
    };

    let resp = AuthTokenResponse { token, user_id: user.id, email: user.email.clone(), name: user.name.clone() };
    (StatusCode::OK, Json(resp)).into_response()
}
