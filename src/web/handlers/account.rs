use axum::{extract::{Path, State}, http::StatusCode, response::{IntoResponse, Redirect}, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_cookies::Cookies;

use crate::{app::AppState, auth::session};
use crate::models::api_key::{ApiKey, scopes};

pub async fn me(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    if let Some(s) = session::get_session(&cookies, &state.cookie_key) {
        let body = json!({
            "user_id": s.user_id,
        });
        (StatusCode::OK, Json(body)).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

pub async fn logout(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    session::clear_session(&cookies, &state.cookie_key);
    StatusCode::NO_CONTENT
}

const LINK_COOKIE: &str = "link_provider";

// List linked identities for the current user
pub async fn list_identities(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    if let Some(s) = session::get_session(&cookies, &state.cookie_key) {
        match state.accounts.list_identities(&s.user_id).await {
            Ok(list) => (StatusCode::OK, Json(json!({ "items": list }))).into_response(),
            Err(e) => {
                tracing::error!(error=?e, "failed to list identities");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

// List all enabled providers for the login page
pub async fn list_providers(State(state): State<AppState>) -> impl IntoResponse {
    match state.accounts.list_providers().await {
        Ok(list) => (StatusCode::OK, Json(json!({ "items": list }))).into_response(),
        Err(e) => {
            tracing::error!(error=?e, "failed to list providers");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// Begin linking a new provider: set a short-lived cookie flag and redirect to provider flow
pub async fn start_link_provider(State(state): State<AppState>, cookies: Cookies, Path(provider): Path<String>) -> impl IntoResponse {
    if session::get_session(&cookies, &state.cookie_key).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut c = tower_cookies::Cookie::new(LINK_COOKIE, provider.clone());
    c.set_path("/");
    c.set_http_only(true);
    c.set_same_site(tower_cookies::cookie::SameSite::Lax);
    c.set_secure(crate::auth::session::is_https());
    cookies.add(c);
    Redirect::temporary(&format!("/auth/{}", provider)).into_response()
}

// Unlink a provider from current user, guarding against removing the last identity
pub async fn unlink_provider(State(state): State<AppState>, cookies: Cookies, Path(provider): Path<String>) -> impl IntoResponse {
    if let Some(s) = session::get_session(&cookies, &state.cookie_key) {
        match state.accounts.count_identities(&s.user_id).await {
            Ok(n) if n <= 1 => return (StatusCode::CONFLICT, Json(json!({"error":"cannot unlink the last identity"}))).into_response(),
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error=?e, "failed counting identities");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        match state.accounts.unlink_identity_by_provider(&s.user_id, &provider).await {
            Ok(0) => StatusCode::NOT_FOUND.into_response(),
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => {
                tracing::error!(error=?e, "failed unlinking identity");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

// Expose a helper used in oidc callback
pub fn get_link_cookie(cookies: &Cookies) -> Option<String> {
    cookies.get(LINK_COOKIE).map(|c| c.value().to_string())
}

pub fn clear_link_cookie(cookies: &Cookies) {
    let mut c = tower_cookies::Cookie::new(LINK_COOKIE, "");
    c.set_path("/");
    cookies.remove(c);
}

// API Key Management

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key: String,  // Only returned once on creation
    pub scopes: String,
    pub created_at: String,
}

/// Create a new API key
pub async fn create_api_key(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(req): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    let Some(s) = session::get_session(&cookies, &state.cookie_key) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Generate random API key
    let key = generate_api_key();
    let key_hash = hash_api_key(&key);

    let now = time::OffsetDateTime::now_utc().to_string();
    let api_key = ApiKey {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: s.user_id.clone(),
        name: req.name,
        key_hash,
        scopes: scopes::PROXY.to_string(),
        created_at: now.clone(),
        last_used_at: None,
        deleted_at: None,
    };

    match state.accounts.create_api_key(api_key.clone()).await {
        Ok(_) => {
            let response = CreateApiKeyResponse {
                id: api_key.id,
                name: api_key.name,
                key,  // Return plaintext key only once
                scopes: api_key.scopes,
                created_at: api_key.created_at,
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!(error=?e, "failed to create API key");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to create API key"}))).into_response()
        }
    }
}

/// List API keys for the current user
pub async fn list_api_keys(
    State(state): State<AppState>,
    cookies: Cookies,
) -> impl IntoResponse {
    let Some(s) = session::get_session(&cookies, &state.cookie_key) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.accounts.list_api_keys(&s.user_id).await {
        Ok(keys) => {
            // Don't expose key_hash to client
            let safe_keys: Vec<_> = keys.into_iter().map(|k| json!({
                "id": k.id,
                "name": k.name,
                "scopes": k.scopes,
                "created_at": k.created_at,
                "last_used_at": k.last_used_at,
            })).collect();
            (StatusCode::OK, Json(json!({"items": safe_keys}))).into_response()
        }
        Err(e) => {
            tracing::error!(error=?e, "failed to list API keys");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to list API keys"}))).into_response()
        }
    }
}

/// Delete (soft delete) an API key
pub async fn delete_api_key(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    let Some(s) = session::get_session(&cookies, &state.cookie_key) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.accounts.soft_delete_api_key(&key_id, &s.user_id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error=?e, "failed to delete API key");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to delete API key"}))).into_response()
        }
    }
}

/// Generate a secure random API key
fn generate_api_key() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const KEY_LEN: usize = 48;

    let mut rng = rand::thread_rng();
    let key: String = (0..KEY_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    format!("oak_{}", key)  // Prefix for easy identification (oauth key)
}

/// Hash API key using SHA-256
fn hash_api_key(key: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}
