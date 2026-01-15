use axum::{extract::{Path, State, Query}, response::{IntoResponse, Redirect}};
use tower_cookies::Cookies;
use crate::app::AppState;

// Starts the OAuth/OIDC flow for a given provider.
pub async fn start(State(state): State<AppState>, cookies: Cookies, Path(provider): Path<String>) -> impl IntoResponse {
    match provider.as_str() {
        "google" => crate::auth::oidc::start_google(&state, cookies).await.into_response(),
        "github" => crate::auth::oidc::start_github(&state, cookies).await.into_response(),
        "dex" => crate::auth::oidc::start_dex(&state, cookies).await.into_response(),
        _ => {
            tracing::warn!(%provider, "unknown provider in auth start");
            Redirect::temporary("/login").into_response()
        }
    }
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
    match provider.as_str() {
        "google" => crate::auth::oidc::callback_google(&state, cookies, q).await.into_response(),
        "github" => crate::auth::oidc::callback_github(&state, cookies, q).await.into_response(),
        "dex" => crate::auth::oidc::callback_dex(&state, cookies, q).await.into_response(),
        _ => {
            tracing::warn!(%provider, "unknown provider in auth callback");
            Redirect::temporary("/").into_response()
        }
    }
}
