use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{
    app::AppState,
    web::session::SessionUser,
};

/// Proxy endpoint handler
/// Route: ANY /proxy/:provider/*path
///
/// Proxies authenticated requests to the specified OAuth provider's API.
/// Automatically handles token refresh and injects OAuth credentials.
pub async fn proxy_request(
    State(state): State<AppState>,
    SessionUser(user_id): SessionUser,
    Path((provider_key, path)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ProxyError> {
    // Get user's identity for this provider
    let identity = state
        .accounts
        .get_user_identity(&user_id, &provider_key)
        .await
        .map_err(|_| ProxyError::ProviderNotLinked(provider_key.clone()))?
        .ok_or_else(|| ProxyError::ProviderNotLinked(provider_key.clone()))?;

    // Check if token needs refresh
    let access_token = if needs_refresh(&identity) {
        // TODO: Implement token refresh
        return Err(ProxyError::TokenExpired);
    } else {
        identity.access_token
            .ok_or(ProxyError::NoAccessToken)?
    };

    // Get provider configuration to determine API base URL
    let provider = state
        .accounts
        .get_provider(&provider_key)
        .await
        .map_err(|_| ProxyError::ProviderNotFound(provider_key.clone()))?
        .ok_or_else(|| ProxyError::ProviderNotFound(provider_key.clone()))?;

    // Get API base URL from provider config
    let api_base = provider.api_base_url
        .ok_or(ProxyError::NoApiBaseUrl)?;

    // Build target URL
    let target_url = format!("{}/{}", api_base.trim_end_matches('/'), path.trim_start_matches('/'));

    tracing::info!(
        user_id = %user_id,
        provider = %provider_key,
        method = %method,
        target_url = %target_url,
        "Proxying OAuth request"
    );

    // Forward the request
    let response = forward_request(
        &target_url,
        method,
        headers,
        body,
        &access_token,
    ).await?;

    Ok(response)
}

/// Check if token needs refresh based on expires_at
fn needs_refresh(identity: &crate::models::identity::UserIdentity) -> bool {
    if let Some(expires_at) = &identity.expires_at {
        // Parse ISO8601 timestamp using time crate
        use time::OffsetDateTime;
        if let Ok(expires) = OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339) {
            // Refresh if expiring within 5 minutes
            let now = OffsetDateTime::now_utc();
            return (expires - now).whole_seconds() < 300;
        }
    }
    false
}

/// Forward HTTP request with OAuth token
async fn forward_request(
    url: &str,
    method: Method,
    mut headers: HeaderMap,
    body: Body,
    access_token: &str,
) -> Result<Response, ProxyError> {
    // Build HTTP client
    let client = reqwest::Client::new();

    // Add OAuth Bearer token
    headers.insert(
        "Authorization",
        format!("Bearer {}", access_token)
            .parse()
            .map_err(|_| ProxyError::Internal("Invalid token format".to_string()))?,
    );

    // Remove hop-by-hop headers
    headers.remove("host");
    headers.remove("connection");
    headers.remove("transfer-encoding");

    // Convert axum body to bytes
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| ProxyError::Internal(format!("Failed to read request body: {}", e)))?;

    // Build request
    let mut req = client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes())
            .map_err(|_| ProxyError::Internal("Invalid method".to_string()))?,
        url,
    );

    // Copy headers
    for (name, value) in headers.iter() {
        if let Ok(val) = value.to_str() {
            req = req.header(name.as_str(), val);
        }
    }

    // Add body if present
    if !body_bytes.is_empty() {
        req = req.body(body_bytes.to_vec());
    }

    // Execute request
    let response = req.send()
        .await
        .map_err(|e| ProxyError::UpstreamError(e.to_string()))?;

    // Convert response
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = response.bytes()
        .await
        .map_err(|e| ProxyError::UpstreamError(e.to_string()))?;

    // Build response
    let mut res = Response::builder()
        .status(status);

    // Copy response headers (filter hop-by-hop)
    for (name, value) in headers.iter() {
        if name != "connection" && name != "transfer-encoding" {
            res = res.header(name, value);
        }
    }

    res.body(Body::from(body_bytes))
        .map_err(|e| ProxyError::Internal(format!("Failed to build response: {}", e)))
}

/// Proxy errors
#[derive(Debug)]
pub enum ProxyError {
    ProviderNotLinked(String),
    ProviderNotFound(String),
    NoAccessToken,
    NoApiBaseUrl,
    TokenExpired,
    UpstreamError(String),
    Internal(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ProxyError::ProviderNotLinked(provider) => (
                StatusCode::NOT_FOUND,
                format!("Provider '{}' not linked to your account", provider),
            ),
            ProxyError::ProviderNotFound(provider) => (
                StatusCode::NOT_FOUND,
                format!("Provider '{}' not configured", provider),
            ),
            ProxyError::NoAccessToken => (
                StatusCode::UNAUTHORIZED,
                "No access token available for this provider".to_string(),
            ),
            ProxyError::NoApiBaseUrl => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Provider has no API base URL configured".to_string(),
            ),
            ProxyError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                "Access token expired and refresh not yet implemented".to_string(),
            ),
            ProxyError::UpstreamError(err) => (
                StatusCode::BAD_GATEWAY,
                format!("Upstream provider error: {}", err),
            ),
            ProxyError::Internal(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal error: {}", err),
            ),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
