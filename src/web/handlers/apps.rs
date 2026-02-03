use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use tower_cookies::Cookies;
use url::Url;

use crate::{
    app::AppState,
    auth::session,
    models::{
        app_redirect_uri::AppRedirectUri,
        application::Application,
    },
};

#[derive(Debug, Serialize)]
pub struct AppSummary {
    id: String,
    name: String,
    client_type: String,
    allowed_scopes: String,
    is_enabled: i32,
    created_at: String,
    updated_at: String,
    has_secret: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateAppRequest {
    pub name: String,
    pub client_type: Option<String>,
    pub allowed_scopes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateAppResponse {
    pub app: AppSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddRedirectUriRequest {
    pub redirect_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct RemoveRedirectUriRequest {
    pub redirect_uri: String,
}

#[derive(Debug, Serialize)]
pub struct RedirectUriResponse {
    pub id: String,
    pub redirect_uri: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ConsentResponse {
    pub app_id: String,
    pub app_name: String,
    pub scopes: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

pub async fn list_apps(
    State(state): State<AppState>,
    cookies: Cookies,
) -> impl IntoResponse {
    let user_id = match session_user_id(&cookies, &state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match state.accounts.list_applications(&user_id).await {
        Ok(apps) => {
            let items: Vec<_> = apps.into_iter().map(app_to_summary).collect();
            Json(json!({ "items": items })).into_response()
        }
        Err(e) => {
            tracing::error!(error=?e, "failed to list applications");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to list applications")
        }
    }
}

pub async fn create_app(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(req): Json<CreateAppRequest>,
) -> impl IntoResponse {
    let user_id = match session_user_id(&cookies, &state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let name = req.name.trim();
    if name.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "App name is required");
    }

    let client_type = normalize_client_type(req.client_type.as_deref());
    if client_type.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Invalid client type");
    }

    let allowed_scopes = normalize_scopes(req.allowed_scopes.as_deref().unwrap_or("proxy"));
    if !validate_scopes(&allowed_scopes) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Allowed scopes must be 'proxy' or 'proxy:{provider}' or 'proxy:{provider}:read|write'",
        );
    }
    let now = OffsetDateTime::now_utc().to_string();
    let app_id = uuid::Uuid::new_v4().to_string();

    let (secret, secret_hash) = if client_type == "confidential" {
        let secret = generate_client_secret();
        let hash = hash_token(&secret);
        (Some(secret), Some(hash))
    } else {
        (None, None)
    };

    let app = Application {
        id: app_id.clone(),
        owner_user_id: user_id,
        name: name.to_string(),
        client_type: client_type.to_string(),
        client_secret_hash: secret_hash,
        allowed_scopes: allowed_scopes.clone(),
        is_enabled: 1,
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    if let Err(e) = state.accounts.save_application(app.clone()).await {
        tracing::error!(error=?e, "failed to save application");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create application");
    }

    let response = CreateAppResponse {
        app: app_to_summary(app),
        client_secret: secret,
    };

    (StatusCode::CREATED, Json(response)).into_response()
}

pub async fn rotate_secret(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(app_id): Path<String>,
) -> impl IntoResponse {
    let user_id = match session_user_id(&cookies, &state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut app = match get_owned_app(&state, &user_id, &app_id).await {
        Ok(app) => app,
        Err(resp) => return resp,
    };

    if !app.client_type.eq_ignore_ascii_case("confidential") {
        return error_response(StatusCode::BAD_REQUEST, "Public apps do not use client secrets");
    }

    let secret = generate_client_secret();
    app.client_secret_hash = Some(hash_token(&secret));
    app.updated_at = OffsetDateTime::now_utc().to_string();

    if let Err(e) = state.accounts.save_application(app).await {
        tracing::error!(error=?e, "failed to rotate secret");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to rotate secret");
    }

    Json(json!({ "client_secret": secret })).into_response()
}

pub async fn list_redirect_uris(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(app_id): Path<String>,
) -> impl IntoResponse {
    let user_id = match session_user_id(&cookies, &state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if get_owned_app(&state, &user_id, &app_id).await.is_err() {
        return error_response(StatusCode::NOT_FOUND, "Application not found");
    }

    match state.accounts.list_app_redirect_uris(&app_id).await {
        Ok(items) => {
            let items: Vec<_> = items
                .into_iter()
                .map(|row| RedirectUriResponse {
                    id: row.id,
                    redirect_uri: row.redirect_uri,
                    created_at: row.created_at,
                })
                .collect();
            Json(json!({ "items": items })).into_response()
        }
        Err(e) => {
            tracing::error!(error=?e, "failed to list redirect uris");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to list redirect URIs")
        }
    }
}

pub async fn add_redirect_uri(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(app_id): Path<String>,
    Json(req): Json<AddRedirectUriRequest>,
) -> impl IntoResponse {
    let user_id = match session_user_id(&cookies, &state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if get_owned_app(&state, &user_id, &app_id).await.is_err() {
        return error_response(StatusCode::NOT_FOUND, "Application not found");
    }

    let redirect_uri = req.redirect_uri.trim();
    if redirect_uri.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Redirect URI is required");
    }
    if !validate_redirect_uri(redirect_uri) {
        return error_response(StatusCode::BAD_REQUEST, "Invalid redirect URI");
    }

    let existing = match state.accounts.list_app_redirect_uris(&app_id).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error=?e, "failed to list redirect uris");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to add redirect URI");
        }
    };
    if existing.iter().any(|r| r.redirect_uri == redirect_uri) {
        return error_response(StatusCode::CONFLICT, "Redirect URI already exists");
    }

    let row = AppRedirectUri {
        id: uuid::Uuid::new_v4().to_string(),
        app_id,
        redirect_uri: redirect_uri.to_string(),
        created_at: OffsetDateTime::now_utc().to_string(),
    };

    if let Err(e) = state.accounts.add_app_redirect_uri(row.clone()).await {
        tracing::error!(error=?e, "failed to add redirect uri");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to add redirect URI");
    }

    Json(RedirectUriResponse {
        id: row.id,
        redirect_uri: row.redirect_uri,
        created_at: row.created_at,
    })
    .into_response()
}

pub async fn remove_redirect_uri(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(app_id): Path<String>,
    Json(req): Json<RemoveRedirectUriRequest>,
) -> impl IntoResponse {
    let user_id = match session_user_id(&cookies, &state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if get_owned_app(&state, &user_id, &app_id).await.is_err() {
        return error_response(StatusCode::NOT_FOUND, "Application not found");
    }

    let redirect_uri = req.redirect_uri.trim();
    if redirect_uri.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Redirect URI is required");
    }

    match state
        .accounts
        .remove_app_redirect_uri(&app_id, redirect_uri)
        .await
    {
        Ok(0) => error_response(StatusCode::NOT_FOUND, "Redirect URI not found"),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error=?e, "failed to remove redirect uri");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to remove redirect URI")
        }
    }
}

pub async fn list_consents(
    State(state): State<AppState>,
    cookies: Cookies,
) -> impl IntoResponse {
    let user_id = match session_user_id(&cookies, &state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let consents = match state.accounts.list_user_consents(&user_id).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error=?e, "failed to list consents");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to list consents");
        }
    };

    let mut items = Vec::new();
    for consent in consents {
        let app_name = match state.accounts.get_application(&consent.app_id).await {
            Ok(Some(app)) => app.name,
            Ok(None) => consent.app_id.clone(),
            Err(e) => {
                tracing::error!(error=?e, "failed to load app for consent");
                consent.app_id.clone()
            }
        };

        items.push(ConsentResponse {
            app_id: consent.app_id,
            app_name,
            scopes: consent.scopes,
            created_at: consent.created_at,
            revoked_at: consent.revoked_at,
        });
    }

    Json(json!({ "items": items })).into_response()
}

pub async fn revoke_consent(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(app_id): Path<String>,
) -> impl IntoResponse {
    let user_id = match session_user_id(&cookies, &state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let consent = match state.accounts.get_user_consent(&user_id, &app_id).await {
        Ok(consent) => consent,
        Err(e) => {
            tracing::error!(error=?e, "failed to get consent");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to revoke consent");
        }
    };

    if consent.is_none() {
        return error_response(StatusCode::NOT_FOUND, "Consent not found");
    }

    if let Err(e) = state.accounts.revoke_user_consent(&user_id, &app_id).await {
        tracing::error!(error=?e, "failed to revoke consent");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to revoke consent");
    }

    StatusCode::NO_CONTENT.into_response()
}

fn app_to_summary(app: Application) -> AppSummary {
    AppSummary {
        id: app.id,
        name: app.name,
        client_type: app.client_type,
        allowed_scopes: app.allowed_scopes,
        is_enabled: app.is_enabled,
        created_at: app.created_at,
        updated_at: app.updated_at,
        has_secret: app.client_secret_hash.is_some(),
    }
}

fn session_user_id(cookies: &Cookies, state: &AppState) -> Result<String, Response> {
    match session::get_session(cookies, &state.cookie_key) {
        Some(s) => Ok(s.user_id),
        None => Err(error_response(StatusCode::UNAUTHORIZED, "Not authenticated")),
    }
}

async fn get_owned_app(state: &AppState, user_id: &str, app_id: &str) -> Result<Application, Response> {
    let app = match state.accounts.get_application(app_id).await {
        Ok(Some(app)) => app,
        Ok(None) => return Err(error_response(StatusCode::NOT_FOUND, "Application not found")),
        Err(e) => {
            tracing::error!(error=?e, "failed to get application");
            return Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load application"));
        }
    };

    if app.owner_user_id != user_id {
        return Err(error_response(StatusCode::NOT_FOUND, "Application not found"));
    }

    Ok(app)
}

fn normalize_client_type(value: Option<&str>) -> String {
    match value.unwrap_or("confidential").to_lowercase().as_str() {
        "public" => "public".to_string(),
        "confidential" => "confidential".to_string(),
        _ => "".to_string(),
    }
}

fn normalize_scopes(value: &str) -> String {
    let mut scopes: Vec<String> = value
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() {
        "proxy".to_string()
    } else {
        scopes.join(" ")
    }
}

fn validate_scopes(value: &str) -> bool {
    value.split_whitespace().all(is_valid_scope)
}

fn is_valid_scope(scope: &str) -> bool {
    if scope == "proxy" {
        return true;
    }
    let Some(rest) = scope.strip_prefix("proxy:") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let mut parts = rest.split(':');
    let Some(provider) = parts.next() else {
        return false;
    };
    if !is_valid_scope_segment(provider) {
        return false;
    }
    match parts.next() {
        None => true,
        Some(action) => {
            if action != "read" && action != "write" {
                return false;
            }
            parts.next().is_none()
        }
    }
}

fn is_valid_scope_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn validate_redirect_uri(value: &str) -> bool {
    match Url::parse(value) {
        Ok(url) => matches!(url.scheme(), "http" | "https") && url.fragment().is_none(),
        Err(_) => false,
    }
}

fn generate_client_secret() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    format!(
        "oapp_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    )
}

fn hash_token(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}
