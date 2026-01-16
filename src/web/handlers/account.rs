use axum::{extract::{Path, State}, http::StatusCode, response::{IntoResponse, Redirect}, Json};
use serde_json::json;
use tower_cookies::Cookies;

use crate::{app::AppState, auth::session};

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
