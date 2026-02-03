use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::collections::HashSet;
use std::future::Future;
use tower_cookies::Cookies;

use crate::app::AppState;
use crate::auth::session;
use crate::models::api_key::scopes;

/// Session extractor that requires authentication
///
/// Supports two authentication methods:
/// 1. Session cookie (sid)
/// 2. Bearer token (Authorization: Bearer <api_key>)
/// 3. Bearer token (Authorization: Bearer <app_access_token>)
///
/// Usage:
/// ```
/// use oauth3::web::session::SessionUser;
/// use axum::response::IntoResponse;
///
/// async fn handler(SessionUser { user_id, .. }: SessionUser) -> impl IntoResponse {
///     // user_id is guaranteed to be present
///     format!("User: {}", user_id)
/// }
/// ```
pub struct SessionUser {
    pub user_id: String,
    pub scopes: Option<String>,
}

struct AuthInfo {
    user_id: String,
    scopes: Option<String>,
}

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            // Try Authorization header first (API key)
            if let Some(auth_header) = parts.headers.get(AUTHORIZATION) {
                if let Ok(auth_str) = auth_header.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        let auth = authenticate_with_bearer(token, state).await?;
                        return Ok(SessionUser {
                            user_id: auth.user_id,
                            scopes: auth.scopes,
                        });
                    }
                }
            }

            // Fall back to session cookie
            let cookies = Cookies::from_request_parts(parts, state)
                .await
                .map_err(|e| {
                    tracing::error!(error = ?e, "Failed to extract cookies");
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "Not authenticated"})),
                    )
                        .into_response()
                })?;

            if let Some(session_data) = session::get_session(&cookies, &state.cookie_key) {
                Ok(SessionUser {
                    user_id: session_data.user_id,
                    scopes: None,
                })
            } else {
                tracing::warn!("No valid session found in cookies");
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Not authenticated"})),
                )
                    .into_response())
            }
        }
    }
}

async fn authenticate_with_bearer(token: &str, state: &AppState) -> Result<AuthInfo, Response> {
    match authenticate_with_api_key(token, state).await? {
        Some(user) => Ok(user),
        None => authenticate_with_app_access_token(token, state).await,
    }
}

/// Authenticate using API key
async fn authenticate_with_api_key(
    api_key: &str,
    state: &AppState,
) -> Result<Option<AuthInfo>, Response> {
    // Hash the provided key
    let key_hash = hash_token(api_key);

    // Look up key in database
    let key_record = state
        .accounts
        .get_api_key_by_hash(&key_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to look up API key");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        })?;

    let Some(key_record) = key_record else {
        return Ok(None);
    };

    // Check if key has proxy scope
    if !has_proxy_scope(&key_record.scopes) {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "API key does not have proxy scope",
        ));
    }

    // Update last used timestamp (fire and forget)
    let accounts = state.accounts.clone();
    let key_id = key_record.id.clone();
    tokio::spawn(async move {
        let _ = accounts.update_api_key_last_used(&key_id).await;
    });

    Ok(Some(AuthInfo {
        user_id: key_record.user_id,
        scopes: Some(key_record.scopes),
    }))
}

async fn authenticate_with_app_access_token(
    token: &str,
    state: &AppState,
) -> Result<AuthInfo, Response> {
    let token_hash = hash_token(token);
    let token_record = state
        .accounts
        .get_app_access_token_by_hash(&token_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to look up app access token");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        })?;

    let Some(token_record) = token_record else {
        return Err(json_error(StatusCode::UNAUTHORIZED, "Invalid access token"));
    };

    if token_record.revoked_at.is_some() {
        return Err(json_error(StatusCode::UNAUTHORIZED, "Invalid access token"));
    }

    if is_expired(&token_record.expires_at) {
        return Err(json_error(StatusCode::UNAUTHORIZED, "Access token expired"));
    }

    if !has_proxy_scope(&token_record.scopes) {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "Access token does not have proxy scope",
        ));
    }

    let app = state
        .accounts
        .get_application(&token_record.app_id)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to load application");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        })?;
    let Some(app) = app else {
        return Err(json_error(StatusCode::UNAUTHORIZED, "Invalid access token"));
    };
    if app.is_enabled != 1 {
        return Err(json_error(StatusCode::UNAUTHORIZED, "Invalid access token"));
    }

    let consent = state
        .accounts
        .get_user_consent(&token_record.user_id, &token_record.app_id)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to load user consent");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        })?;
    let Some(consent) = consent else {
        return Err(json_error(StatusCode::FORBIDDEN, "Consent required"));
    };
    if consent.revoked_at.is_some()
        || !scopes_within(&token_record.scopes, &consent.scopes)
    {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "Consent does not allow requested scopes",
        ));
    }

    let accounts = state.accounts.clone();
    let token_id = token_record.id.clone();
    tokio::spawn(async move {
        let _ = accounts.update_app_access_token_last_used(&token_id).await;
    });

    Ok(AuthInfo {
        user_id: token_record.user_id,
        scopes: Some(token_record.scopes),
    })
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn has_proxy_scope(scopes: &str) -> bool {
    scopes.split_whitespace().any(|s| s == scopes::PROXY || s.starts_with("proxy:"))
}

fn scopes_within(requested: &str, allowed: &str) -> bool {
    let req: HashSet<&str> = requested
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect();
    let allow: HashSet<&str> = allowed
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect();
    req.is_subset(&allow)
}

fn is_expired(timestamp: &str) -> bool {
    if let Ok(expires) = time::OffsetDateTime::parse(
        timestamp,
        &time::format_description::well_known::Rfc3339,
    ) {
        return time::OffsetDateTime::now_utc() > expires;
    }
    false
}

/// Hash token using SHA-256
fn hash_token(key: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}
