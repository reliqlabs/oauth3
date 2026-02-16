use axum::{extract::{Path, State, Query}, response::IntoResponse};
use tower_cookies::Cookies;
use crate::app::AppState;

#[derive(Debug, serde::Deserialize)]
pub struct AuthStartQuery {
    pub return_to: Option<String>,
}

// Starts the OAuth/OIDC flow for a given provider.
pub async fn start(State(state): State<AppState>, cookies: Cookies, Path(provider): Path<String>, Query(q): Query<AuthStartQuery>) -> impl IntoResponse {
    // If the caller passed a return_to URL, store it as a cookie on *this* domain
    // so the post-login handler can redirect back to the calling app.
    if let Some(ref return_to) = q.return_to {
        crate::auth::session::set_login_return_to(&cookies, return_to);
    }
    crate::auth::oidc::start(&state, cookies, &provider).await.into_response()
}

// Handles the callback/redirect from the provider.
#[derive(Debug, serde::Deserialize)]
pub struct AuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub async fn callback(State(state): State<AppState>, cookies: Cookies, Path(provider): Path<String>, Query(q): Query<AuthCallbackQuery>) -> impl IntoResponse {
    crate::auth::oidc::callback(&state, cookies, &provider, q).await.into_response()
}
