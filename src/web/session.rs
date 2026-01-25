use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
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
///
/// Usage:
/// ```
/// use oauth3::web::session::SessionUser;
/// use axum::response::IntoResponse;
///
/// async fn handler(SessionUser(user_id): SessionUser) -> impl IntoResponse {
///     // user_id is guaranteed to be present
///     format!("User: {}", user_id)
/// }
/// ```
pub struct SessionUser(pub String);

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
                        return authenticate_with_api_key(token, state).await;
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
                Ok(SessionUser(session_data.user_id))
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Not authenticated"})),
                )
                    .into_response())
            }
        }
    }
}

/// Authenticate using API key
async fn authenticate_with_api_key(
    api_key: &str,
    state: &AppState,
) -> Result<SessionUser, Response> {
    // Hash the provided key
    let key_hash = hash_api_key(api_key);

    // Look up key in database
    let key_record = state
        .accounts
        .get_api_key_by_hash(&key_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to look up API key");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        })?;

    let key_record = key_record.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid API key"})),
        )
            .into_response()
    })?;

    // Check if key has proxy scope
    if !key_record.has_scope(scopes::PROXY) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "API key does not have proxy scope"})),
        )
            .into_response());
    }

    // Update last used timestamp (fire and forget)
    let accounts = state.accounts.clone();
    let key_id = key_record.id.clone();
    tokio::spawn(async move {
        let _ = accounts.update_api_key_last_used(&key_id).await;
    });

    Ok(SessionUser(key_record.user_id))
}

/// Hash API key using SHA-256
fn hash_api_key(key: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}
