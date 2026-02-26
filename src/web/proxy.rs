use axum::{
    body::Body,
    extract::{OriginalUri, Path, State},
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
    SessionUser { user_id, scopes }: SessionUser,
    Path((provider_key, path)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Body,
) -> Result<Response, ProxyError> {
    tracing::info!(
        user_id = %user_id,
        provider = %provider_key,
        path = %path,
        method = %method,
        "Starting proxy request"
    );

    if !scope_allows_provider(scopes.as_deref(), &provider_key) {
        tracing::warn!(
            user_id = %user_id,
            provider = %provider_key,
            "Token scope does not allow proxy access to provider"
        );
        return Err(ProxyError::InsufficientScope(provider_key));
    }

    // Get user's identity for this provider
    let identity = state
        .accounts
        .get_user_identity(&user_id, &provider_key)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, user_id = %user_id, provider = %provider_key, "Failed to get user identity");
            ProxyError::ProviderNotLinked(provider_key.clone())
        })?
        .ok_or_else(|| {
            tracing::warn!(user_id = %user_id, provider = %provider_key, "Identity not found");
            ProxyError::ProviderNotLinked(provider_key.clone())
        })?;

    // Check if token needs refresh
    let access_token = if needs_refresh(&identity) {
        tracing::warn!(user_id = %user_id, provider = %provider_key, "Token expired");
        return Err(ProxyError::TokenExpired);
    } else {
        identity.access_token
            .ok_or_else(|| {
                tracing::error!(user_id = %user_id, provider = %provider_key, "No access token");
                ProxyError::NoAccessToken
            })?
    };

    // Get provider configuration to determine API base URL
    let provider = state
        .accounts
        .get_provider(&provider_key)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, provider = %provider_key, "Failed to get provider config");
            ProxyError::ProviderNotFound(provider_key.clone())
        })?
        .ok_or_else(|| {
            tracing::error!(provider = %provider_key, "Provider config not found");
            ProxyError::ProviderNotFound(provider_key.clone())
        })?;
    if provider.is_enabled != 1 {
        tracing::warn!(provider = %provider_key, "Provider is disabled");
        return Err(ProxyError::ProviderDisabled(provider_key));
    }

    // Get API base URL from provider config
    let api_base = provider.api_base_url
        .ok_or_else(|| {
            tracing::error!(provider = %provider_key, "No API base URL configured");
            ProxyError::NoApiBaseUrl
        })?;

    // Validate path does not contain directory traversal or host confusion
    if path.contains("..") || path.starts_with("//") || path.contains('@') {
        return Err(ProxyError::Internal("Invalid path".to_string()));
    }

    // Build target URL
    let base_url = format!("{}/{}", api_base.trim_end_matches('/'), path.trim_start_matches('/'));
    let target_url = match uri.query().filter(|q| !q.is_empty()) {
        Some(query) => format!("{}?{}", base_url, query),
        None => base_url,
    };

    // Verify the final URL's host still matches the configured API base host (SSRF protection)
    if let (Ok(target_parsed), Ok(base_parsed)) = (url::Url::parse(&target_url), url::Url::parse(&api_base)) {
        if target_parsed.host() != base_parsed.host() {
            tracing::error!(target = %target_url, base = %api_base, "Proxy target host mismatch");
            return Err(ProxyError::Internal("Target host mismatch".to_string()));
        }
    }

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
    ).await.map_err(|e| {
        tracing::error!(error = ?e, target_url = %target_url, "Forward request failed");
        e
    })?;

    tracing::info!(user_id = %user_id, provider = %provider_key, "Proxy request successful");
    Ok(response)
}

/// Check if token needs refresh based on expires_at
fn needs_refresh(identity: &crate::models::identity::UserIdentity) -> bool {
    if let Some(expires_at) = &identity.expires_at {
        use time::OffsetDateTime;
        if let Ok(expires) = OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339) {
            // Refresh if expiring within 5 minutes
            let now = OffsetDateTime::now_utc();
            return (expires - now).whole_seconds() < 300;
        }
        // Unparseable timestamp — treat as needing refresh (fail closed)
        return true;
    }
    false
}

fn scope_allows_provider(scopes: Option<&str>, provider: &str) -> bool {
    let Some(scopes) = scopes else {
        return true;
    };
    let provider_prefix = format!("{}:", provider);
    for scope in scopes.split_whitespace() {
        if scope == "proxy" {
            return true;
        }
        if let Some(rest) = scope.strip_prefix("proxy:") {
            if rest == provider || rest.starts_with(&provider_prefix) {
                return true;
            }
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

    // Convert axum body to bytes (10 MB limit to prevent OOM)
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
    let body_bytes = axum::body::to_bytes(body, MAX_BODY_SIZE)
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
    ProviderDisabled(String),
    NoAccessToken,
    NoApiBaseUrl,
    TokenExpired,
    InsufficientScope(String),
    UpstreamError(String),
    Internal(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "Proxy error response");

        let (status, message) = match self {
            ProxyError::ProviderNotLinked(provider) => (
                StatusCode::NOT_FOUND,
                format!("Provider '{}' not linked to your account", provider),
            ),
            ProxyError::ProviderNotFound(provider) => (
                StatusCode::NOT_FOUND,
                format!("Provider '{}' not configured", provider),
            ),
            ProxyError::ProviderDisabled(provider) => (
                StatusCode::FORBIDDEN,
                format!("Provider '{}' is disabled", provider),
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
            ProxyError::InsufficientScope(provider) => (
                StatusCode::FORBIDDEN,
                format!("Token scope does not allow access to provider '{}'", provider),
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

#[cfg(test)]
mod tests {
    use super::scope_allows_provider;

    #[test]
    fn scope_allows_provider_for_session_cookie() {
        assert!(scope_allows_provider(None, "google"));
    }

    #[test]
    fn scope_allows_provider_for_proxy_scope() {
        assert!(scope_allows_provider(Some("proxy"), "google"));
        assert!(scope_allows_provider(Some("proxy other"), "github"));
    }

    #[test]
    fn scope_allows_provider_for_provider_scopes() {
        assert!(scope_allows_provider(Some("proxy:google"), "google"));
        assert!(scope_allows_provider(Some("proxy:google:read"), "google"));
        assert!(!scope_allows_provider(Some("proxy:google"), "github"));
    }
}
