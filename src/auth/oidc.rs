use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use tower_cookies::Cookies;
use openidconnect::OAuth2TokenResponse;
use crate::{app::AppState, auth::session, models::identity::NewIdentity, web::handlers::account};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcMode {
    Placeholder,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType {
    Oidc,
    OAuth2,
}

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub provider_type: ProviderType,
    pub mode: OidcMode,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub issuer: Option<String>,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub scopes: Option<String>,
    pub redirect_path: String,
}

#[derive(Debug, Clone)]
pub struct OidcSettings {
    pub public_base_url: String,
}

impl OidcSettings {
    pub fn from_config(cfg: &crate::config::AppConfig) -> anyhow::Result<Self> {
        let public_base_url = cfg.server.public_url.clone();
        Ok(Self {
            public_base_url,
        })
    }

    pub fn redirect_url(&self, provider_redirect_path: &str) -> String {
        format!("{}{}", self.public_base_url.trim_end_matches('/'), provider_redirect_path)
    }
}

const OIDC_TMP_COOKIE_PREFIX: &str = "oidc_tmp_";

fn get_tmp_cookie_name(provider: &str) -> String {
    format!("{}{}", OIDC_TMP_COOKIE_PREFIX, provider)
}

fn redirect_after_login(cookies: &Cookies, config: &crate::config::AppConfig, user_id: &str, default_path: &str) -> Redirect {
    if let Some(path) = session::take_login_return_to(cookies) {
        if is_trusted_redirect(&path, &config.server.public_url) {
            // For trusted return_to URLs, append a signed session token
            // so the calling app can authenticate with OAuth3 via Bearer token.
            if let Some(token) = session::create_session_token(config, user_id) {
                let separator = if path.contains('?') { "&" } else { "?" };
                let url = format!("{}{}token={}", path, separator, urlencoding::encode(&token));
                return Redirect::temporary(&url);
            }
            return Redirect::temporary(&path);
        }
        // Untrusted external URL — redirect without attaching token
        tracing::warn!(return_to = %path, "Blocked token attachment to untrusted redirect URL");
        if path.starts_with('/') && !path.starts_with("//") {
            return Redirect::temporary(&path);
        }
    }
    Redirect::temporary(default_path)
}

/// Check if a redirect URL is trusted for token attachment.
/// Allows relative paths and same-origin URLs unconditionally.
/// For cross-origin URLs, checks ALLOWED_RETURN_TO_ORIGINS env var.
fn is_trusted_redirect(url: &str, public_url: &str) -> bool {
    // Relative paths (but not protocol-relative //) are always trusted
    if url.starts_with('/') && !url.starts_with("//") {
        return true;
    }

    let Ok(target) = url::Url::parse(url) else { return false };

    // Same origin as our public URL
    if let Ok(base) = url::Url::parse(public_url) {
        if target.origin() == base.origin() {
            return true;
        }
    }

    // Check against allowed redirect origins from environment
    if let Ok(allowed) = std::env::var("ALLOWED_RETURN_TO_ORIGINS") {
        for origin in allowed.split(',') {
            let origin = origin.trim();
            if let Ok(allowed_url) = url::Url::parse(origin) {
                if target.origin() == allowed_url.origin() {
                    return true;
                }
            }
        }
        return false; // Origins configured but none matched
    }

    // No allowlist configured — warn and allow for backwards compatibility
    tracing::warn!(
        return_to = %url,
        "No ALLOWED_RETURN_TO_ORIGINS configured; allowing external redirect. \
         Set ALLOWED_RETURN_TO_ORIGINS to restrict."
    );
    true
}

fn write_tmp_state_generic(cookies: &Cookies, key: &tower_cookies::Key, provider: &str, v: &TmpAuthState) -> anyhow::Result<()> {
    let payload = serde_json::to_string(v)?;
    let mut c = tower_cookies::Cookie::new(get_tmp_cookie_name(provider), payload);
    c.set_path("/");
    c.set_http_only(true);
    c.set_same_site(tower_cookies::cookie::SameSite::Lax);
    c.set_secure(session::is_https());
    cookies.private(key).add(c);
    Ok(())
}

fn take_tmp_state_generic(cookies: &Cookies, key: &tower_cookies::Key, provider: &str) -> anyhow::Result<Option<TmpAuthState>> {
    let name = get_tmp_cookie_name(provider);
    if let Some(c) = cookies.private(key).get(&name) {
        let v: TmpAuthState = serde_json::from_str(c.value())?;
        cookies.private(key).remove(c);
        return Ok(Some(v));
    }
    Ok(None)
}

use crate::models::provider::Provider;

impl From<Provider> for ProviderConfig {
    fn from(p: Provider) -> Self {
        let provider_type = match p.provider_type.to_lowercase().as_str() {
            "oauth2" => ProviderType::OAuth2,
            _ => ProviderType::Oidc,
        };
        let mode = match p.mode.to_lowercase().as_str() {
            "live" => OidcMode::Live,
            _ => OidcMode::Placeholder,
        };
        Self {
            name: p.name,
            provider_type,
            mode,
            client_id: p.client_id,
            client_secret: p.client_secret,
            issuer: p.issuer,
            auth_url: p.auth_url,
            token_url: p.token_url,
            scopes: p.scopes,
            redirect_path: p.redirect_path,
        }
    }
}

pub async fn start(state: &AppState, cookies: Cookies, provider_key: &str) -> impl IntoResponse {
    let provider = match state.accounts.get_provider(provider_key).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            tracing::warn!(%provider_key, "provider not found in db");
            return Redirect::temporary("/login").into_response();
        }
        Err(e) => {
            tracing::error!(%provider_key, error=?e, "failed to fetch provider from db");
            return Redirect::temporary("/login").into_response();
        }
    };
    if provider.is_enabled != 1 {
        tracing::warn!(%provider_key, "provider is disabled");
        return Redirect::temporary("/login").into_response();
    }
    let config = ProviderConfig::from(provider);

    match config.mode {
        OidcMode::Placeholder => {
            Redirect::temporary(&format!("/auth/callback/{}", provider_key)).into_response()
        }
        OidcMode::Live => {
            match config.provider_type {
                ProviderType::Oidc => match start_oidc_live(state, cookies, provider_key, &config).await {
                    Ok(r) => r.into_response(),
                    Err(e) => {
                        tracing::error!(provider=%provider_key, error=?e, "oidc start failed");
                        Redirect::temporary("/login").into_response()
                    }
                },
                ProviderType::OAuth2 => match start_oauth2_live(state, cookies, provider_key, &config).await {
                    Ok(r) => r.into_response(),
                    Err(e) => {
                        tracing::error!(provider=%provider_key, error=?e, "oauth2 start failed");
                        Redirect::temporary("/login").into_response()
                    }
                },
            }
        }
    }
}

pub async fn callback(state: &AppState, cookies: Cookies, provider_key: &str, q: crate::web::handlers::auth::AuthCallbackQuery) -> impl IntoResponse {
    let provider = match state.accounts.get_provider(provider_key).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            tracing::warn!(%provider_key, "provider not found in db (callback)");
            return Redirect::temporary("/login").into_response();
        }
        Err(e) => {
            tracing::error!(%provider_key, error=?e, "failed to fetch provider from db (callback)");
            return Redirect::temporary("/login").into_response();
        }
    };
    if provider.is_enabled != 1 {
        tracing::warn!(%provider_key, "provider is disabled (callback)");
        return Redirect::temporary("/login").into_response();
    }
    let config = ProviderConfig::from(provider);

    if matches!(config.mode, OidcMode::Live) {
        let res = match config.provider_type {
            ProviderType::Oidc => callback_oidc_live(state, cookies, provider_key, &config, q).await,
            ProviderType::OAuth2 => callback_oauth2_live(state, cookies, provider_key, &config, q).await,
        };

        match res {
            Ok(resp) => return resp,
            Err(e) => {
                tracing::error!(provider=%provider_key, error=?e, "callback failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("Callback failed: {:?}", e)).into_response();
            }
        }
    }

    // Placeholder behavior
    if let Some(sess) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(link_provider) = account::get_link_cookie(&cookies, &state.cookie_key) {
            if link_provider == provider_key {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let sub = format!("{}-placeholder-sub", provider_key);
                let new_identity = NewIdentity { 
                    id: &identity_id, 
                    user_id: &sess.user_id, 
                    provider_key, 
                    subject: &sub, 
                    email: Some(&format!("{}@example.com", provider_key)), 
                    access_token: None,
                    refresh_token: None,
                    expires_at: None,
                    scopes: None,
                    claims: None 
                };
                if let Err(e) = state.accounts.link_identity(new_identity).await {
                    tracing::error!(provider=%provider_key, error=?e, "failed to link identity (placeholder)");
                }
                account::clear_link_cookie(&cookies, &state.cookie_key);
                return Redirect::temporary("/account").into_response();
            }
        }
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    session::set_session(&cookies, &state.cookie_key, &user_id, 60);
    redirect_after_login(&cookies, &state.config, &user_id, "/").into_response()
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TmpAuthState {
    state: String,
    nonce: String,
    pkce_verifier: String,
}

async fn start_oidc_live(state: &AppState, cookies: Cookies, provider_key: &str, config: &ProviderConfig) -> anyhow::Result<Redirect> {
    use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
    use openidconnect::{AuthenticationFlow, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope};

    let issuer_url = config.issuer.as_ref().ok_or_else(|| anyhow::anyhow!("missing issuer for {}", provider_key))?;
    let issuer = IssuerUrl::new(issuer_url.clone())?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client).await?;

    let client_id = ClientId::new(config.client_id.clone().ok_or_else(|| anyhow::anyhow!("missing client_id for {}", provider_key))?);
    let client_secret = ClientSecret::new(config.client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing client_secret for {}", provider_key))?);
    
    let redirect_uri = state.oidc.redirect_url(&config.redirect_path);
    let redirect_url = RedirectUrl::new(redirect_uri)?;

    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(redirect_url);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = {
        let mut request = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            );
            
        if let Some(s) = &config.scopes {
            for scope in s.split_whitespace() {
                request = request.add_scope(Scope::new(scope.to_string()));
            }
        } else {
            // Default scopes for OIDC
            request = request
                .add_scope(Scope::new("openid".to_string()))
                .add_scope(Scope::new("email".to_string()))
                .add_scope(Scope::new("profile".to_string()));
                
            // Google does not like offline_access scope
            if provider_key != "google" {
                request = request.add_scope(Scope::new("offline_access".to_string()));
            }
        }
        
        // Google specific: access_type=offline and prompt=consent to get a refresh token
        if provider_key == "google" {
            request = request.add_extra_param("access_type", "offline");
            request = request.add_extra_param("prompt", "consent");
        }

        request.set_pkce_challenge(pkce_challenge).url()
    };

    let tmp = TmpAuthState {
        state: csrf_token.secret().to_string(),
        nonce: nonce.secret().to_string(),
        pkce_verifier: pkce_verifier.secret().to_string(),
    };
    write_tmp_state_generic(&cookies, &state.cookie_key, provider_key, &tmp)?;

    Ok(Redirect::temporary(auth_url.as_str()))
}

async fn callback_oidc_live(state: &AppState, cookies: Cookies, provider_key: &str, config: &ProviderConfig, q: crate::web::handlers::auth::AuthCallbackQuery) -> anyhow::Result<axum::response::Response> {
    use openidconnect::core::{CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata};
    use openidconnect::{AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl, TokenResponse};

    if let Some(err) = q.error {
        return Err(anyhow::anyhow!("provider_error: {}", err));
    }
    let code = q.code.ok_or_else(|| anyhow::anyhow!("missing code"))?;
    let state_param = q.state.ok_or_else(|| anyhow::anyhow!("missing state"))?;

    let tmp = take_tmp_state_generic(&cookies, &state.cookie_key, provider_key)?.ok_or_else(|| anyhow::anyhow!("missing stored auth state"))?;
    if tmp.state != state_param { return Err(anyhow::anyhow!("state mismatch")); }

    let issuer_url = config.issuer.as_ref().ok_or_else(|| anyhow::anyhow!("missing issuer for {}", provider_key))?;
    let issuer = IssuerUrl::new(issuer_url.clone())?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client).await?;
    let client_id = ClientId::new(config.client_id.clone().ok_or_else(|| anyhow::anyhow!("missing client_id for {}", provider_key))?);
    let client_secret = ClientSecret::new(config.client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing client_secret for {}", provider_key))?);
    
    let redirect_uri = state.oidc.redirect_url(&config.redirect_path);
    let redirect_url = RedirectUrl::new(redirect_uri.clone())?;
    
    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(redirect_url);

    let token_resp = match client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(tmp.pkce_verifier))
        .request_async(async_http_client)
        .await {
            Ok(r) => r,
            Err(e) => {
                if let openidconnect::RequestTokenError::ServerResponse(err) = &e {
                    tracing::error!(provider=%provider_key, error=?err, redirect_uri=%redirect_uri, "OIDC token exchange server error response");
                } else {
                    tracing::error!(provider=%provider_key, error=?e, redirect_uri=%redirect_uri, "OIDC token exchange failed");
                }
                return Err(anyhow::anyhow!("OIDC token exchange failed: {:?}", e));
            }
        };

    let access_token = token_resp.access_token().secret().to_string();
    let refresh_token = token_resp.refresh_token().map(|t: &openidconnect::RefreshToken| t.secret().to_string());
    let expires_at = token_resp.expires_in().map(|d: std::time::Duration| {
        {
                let dt = time::OffsetDateTime::now_utc() + d;
                dt.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| dt.to_string())
            }
    });
    let scopes = token_resp.scopes().map(|s| {
        s.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ")
    });

    let id_token = token_resp.id_token().ok_or_else(|| anyhow::anyhow!("missing id_token"))?;
    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    let claims: CoreIdTokenClaims = id_token.claims(&id_token_verifier, &Nonce::new(tmp.nonce))?.clone();

    let sub = claims.subject().as_str().to_string();
    let email: Option<String> = claims.email().map(|e| e.to_string());
    let name: Option<String> = claims.name().and_then(|n| n.get(None)).map(|v| v.to_string());

    if let Some(current) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(link_provider) = account::get_link_cookie(&cookies, &state.cookie_key) {
            if link_provider == provider_key {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let new_identity = NewIdentity { 
                    id: &identity_id, 
                    user_id: &current.user_id, 
                    provider_key, 
                    subject: &sub, 
                    email: email.as_deref(), 
                    access_token: Some(&access_token),
                    refresh_token: refresh_token.as_deref(),
                    expires_at: expires_at.as_deref(),
                    scopes: scopes.as_deref(),
                    claims: None 
                };
                state.accounts.link_identity(new_identity).await?;
                account::clear_link_cookie(&cookies, &state.cookie_key);
                return Ok(Redirect::temporary("/account").into_response());
            }
        }
    }

    if let Some(user) = state.accounts.find_user_by_identity(provider_key, &sub).await? {
        state.accounts.update_identity_tokens(provider_key, &sub, &access_token, refresh_token.as_deref(), expires_at.as_deref(), scopes.as_deref()).await?;
        session::set_session(&cookies, &state.cookie_key, &user.id, 60);
        return Ok(redirect_after_login(&cookies, &state.config, &user.id, "/").into_response());
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    let identity_id = uuid::Uuid::new_v4().to_string();
    let new_user = crate::models::user::NewUser { id: &user_id, primary_email: email.as_deref(), display_name: name.as_deref() };
    let new_identity = NewIdentity {
        id: &identity_id,
        user_id: &user_id,
        provider_key,
        subject: &sub,
        email: email.as_deref(),
        access_token: Some(&access_token),
        refresh_token: refresh_token.as_deref(),
        expires_at: expires_at.as_deref(),
        scopes: scopes.as_deref(),
        claims: None
    };
    let user = state.accounts.create_user_and_link(new_user, new_identity).await?;
    session::set_session(&cookies, &state.cookie_key, &user.id, 60);
    Ok(redirect_after_login(&cookies, &state.config, &user.id, "/").into_response())
}

async fn start_oauth2_live(state: &AppState, cookies: Cookies, provider_key: &str, config: &ProviderConfig) -> anyhow::Result<Redirect> {
    use oauth2::{AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, TokenUrl, Scope};
    use oauth2::basic::BasicClient;

    let client_id = ClientId::new(config.client_id.clone().ok_or_else(|| anyhow::anyhow!("missing client_id for {}", provider_key))?);
    let client_secret = ClientSecret::new(config.client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing client_secret for {}", provider_key))?);
    let auth_url = AuthUrl::new(config.auth_url.clone().ok_or_else(|| anyhow::anyhow!("missing auth_url for {}", provider_key))?)?;
    let token_url = TokenUrl::new(config.token_url.clone().ok_or_else(|| anyhow::anyhow!("missing token_url for {}", provider_key))?)?;
    
    let redirect_uri = state.oidc.redirect_url(&config.redirect_path);
    let redirect_url = RedirectUrl::new(redirect_uri)?;

    let client = apply_oauth2_auth_type(
        provider_key,
        BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_redirect_uri(redirect_url),
    );

    let (auth_url, csrf_state) = {
        let mut request = client.authorize_url(CsrfToken::new_random);
        
        if let Some(s) = &config.scopes {
            for scope in s.split_whitespace() {
                request = request.add_scope(Scope::new(scope.to_string()));
            }
        } else {
            // Default scopes for GitHub (since it's the only one we handle special logic for)
            request = request
                .add_scope(Scope::new("user:email".to_string()))
                .add_scope(Scope::new("read:user".to_string()));
        }
        
        request.url()
    };

    let tmp = TmpAuthState {
        state: csrf_state.secret().to_string(),
        nonce: String::new(),
        pkce_verifier: String::new(),
    };
    write_tmp_state_generic(&cookies, &state.cookie_key, provider_key, &tmp)?;

    Ok(Redirect::temporary(auth_url.as_str()))
}

async fn callback_oauth2_live(state: &AppState, cookies: Cookies, provider_key: &str, config: &ProviderConfig, q: crate::web::handlers::auth::AuthCallbackQuery) -> anyhow::Result<axum::response::Response> {
    use oauth2::{AuthUrl, ClientId, ClientSecret, AuthorizationCode, RedirectUrl, TokenUrl};
    use oauth2::basic::BasicClient;
    use oauth2::TokenResponse;

    if let Some(err) = q.error {
        return Err(anyhow::anyhow!("provider_error: {}", err));
    }
    let code = q.code.ok_or_else(|| anyhow::anyhow!("missing code"))?;
    let state_param = q.state.ok_or_else(|| anyhow::anyhow!("missing state"))?;

    let tmp = take_tmp_state_generic(&cookies, &state.cookie_key, provider_key)?.ok_or_else(|| anyhow::anyhow!("missing stored auth state"))?;
    if tmp.state != state_param {
        return Err(anyhow::anyhow!("state mismatch"));
    }

    let client_id = ClientId::new(config.client_id.clone().ok_or_else(|| anyhow::anyhow!("missing client_id for {}", provider_key))?);
    let client_secret = ClientSecret::new(config.client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing client_secret for {}", provider_key))?);
    let auth_url = AuthUrl::new(config.auth_url.clone().ok_or_else(|| anyhow::anyhow!("missing auth_url for {}", provider_key))?)?;
    let token_url = TokenUrl::new(config.token_url.clone().ok_or_else(|| anyhow::anyhow!("missing token_url for {}", provider_key))?)?;
    
    let redirect_uri = state.oidc.redirect_url(&config.redirect_path);
    let redirect_url = RedirectUrl::new(redirect_uri.clone())?;

    let client = apply_oauth2_auth_type(
        provider_key,
        BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_redirect_uri(redirect_url),
    );

    let token_resp = match client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(provider=%provider_key, error=?e, redirect_uri=%redirect_uri, "OAuth2 token exchange failed");
                return Err(anyhow::anyhow!("OAuth2 token exchange failed: {:?}", e));
            }
        };

    let access_token = token_resp.access_token().secret().to_string();
    let refresh_token = token_resp.refresh_token().map(|t: &oauth2::RefreshToken| t.secret().to_string());
    let expires_at = token_resp.expires_in().map(|d: std::time::Duration| {
        {
                let dt = time::OffsetDateTime::now_utc() + d;
                dt.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| dt.to_string())
            }
    });
    let scopes = token_resp.scopes().map(|s| {
        s.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ")
    });

    // Provider specific user info fetching (GitHub example)
    if provider_key == "github" {
        return fetch_github_user_and_login(state, cookies, &access_token, refresh_token.as_deref(), expires_at.as_deref(), scopes.as_deref()).await;
    }

    Err(anyhow::anyhow!("unsupported oauth2 provider: {}", provider_key))
}

async fn fetch_github_user_and_login(
    state: &AppState, 
    cookies: Cookies, 
    access_token: &str, 
    refresh_token: Option<&str>, 
    expires_at: Option<&str>,
    scopes: Option<&str>
) -> anyhow::Result<axum::response::Response> {
    let client = reqwest::Client::new();
    let user_info: serde_json::Value = client.get("https://api.github.com/user")
        .header("Authorization", format!("token {}", access_token))
        .header("User-Agent", "oauth3")
        .send().await?
        .json().await?;

    let sub = user_info["id"].as_i64().ok_or_else(|| anyhow::anyhow!("missing github id"))?.to_string();
    let email = user_info["email"].as_str().map(|s| s.to_string());
    let name = user_info["name"].as_str().or(user_info["login"].as_str()).map(|s| s.to_string());

    if let Some(current) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(link_provider) = account::get_link_cookie(&cookies, &state.cookie_key) {
            if link_provider == "github" {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let new_identity = NewIdentity { 
                    id: &identity_id, 
                    user_id: &current.user_id, 
                    provider_key: "github", 
                    subject: &sub, 
                    email: email.as_deref(), 
                    access_token: Some(access_token),
                    refresh_token,
                    expires_at,
                    scopes,
                    claims: None 
                };
                state.accounts.link_identity(new_identity).await?;
                account::clear_link_cookie(&cookies, &state.cookie_key);
                return Ok(Redirect::temporary("/account").into_response());
            }
        }
    }

    if let Some(user) = state.accounts.find_user_by_identity("github", &sub).await? {
        state.accounts.update_identity_tokens("github", &sub, access_token, refresh_token, expires_at, scopes).await?;
        session::set_session(&cookies, &state.cookie_key, &user.id, 60);
        return Ok(redirect_after_login(&cookies, &state.config, &user.id, "/").into_response());
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    let identity_id = uuid::Uuid::new_v4().to_string();
    let new_user = crate::models::user::NewUser { id: &user_id, primary_email: email.as_deref(), display_name: name.as_deref() };
    let new_identity = NewIdentity {
        id: &identity_id,
        user_id: &user_id,
        provider_key: "github",
        subject: &sub,
        email: email.as_deref(),
        access_token: Some(access_token),
        refresh_token,
        expires_at,
        scopes,
        claims: None
    };
    let user = state.accounts.create_user_and_link(new_user, new_identity).await?;
    session::set_session(&cookies, &state.cookie_key, &user.id, 60);
    Ok(redirect_after_login(&cookies, &state.config, &user.id, "/").into_response())
}

pub async fn refresh_token(state: &AppState, provider_key: &str, subject: &str) -> anyhow::Result<()> {
    let provider = state.accounts.get_provider(provider_key).await?
        .ok_or_else(|| anyhow::anyhow!("provider not found"))?;
    let config = ProviderConfig::from(provider);
    
    let identity = state.accounts.list_identities_by_subject(provider_key, subject).await?
        .ok_or_else(|| anyhow::anyhow!("identity not found"))?;
    
    let refresh_token = identity.refresh_token.ok_or_else(|| anyhow::anyhow!("no refresh token available"))?;

    match config.provider_type {
        ProviderType::Oidc => {
            use openidconnect::core::{CoreClient, CoreProviderMetadata};
            use openidconnect::{ClientId, ClientSecret, IssuerUrl, RefreshToken};

            let issuer_url = config.issuer.as_ref().ok_or_else(|| anyhow::anyhow!("missing issuer"))?;
            let issuer = IssuerUrl::new(issuer_url.clone())?;
            let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client).await?;
            let client_id = ClientId::new(config.client_id.ok_or_else(|| anyhow::anyhow!("missing client_id"))?);
            let client_secret = ClientSecret::new(config.client_secret.ok_or_else(|| anyhow::anyhow!("missing client_secret"))?);

            let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret));
            let token_resp = client
                .exchange_refresh_token(&RefreshToken::new(refresh_token))
                .request_async(async_http_client)
                .await?;

            let access_token = token_resp.access_token().secret().to_string();
            let new_refresh_token = token_resp.refresh_token().map(|t: &openidconnect::RefreshToken| t.secret().to_string());
            let expires_at = token_resp.expires_in().map(|d: std::time::Duration| {
                let dt = time::OffsetDateTime::now_utc() + d;
                dt.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| dt.to_string())
            });
            let new_scopes = token_resp.scopes().map(|s| {
                s.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ")
            });

            state.accounts.update_identity_tokens(provider_key, subject, &access_token, new_refresh_token.as_deref(), expires_at.as_deref(), new_scopes.as_deref()).await?;
        }
        ProviderType::OAuth2 => {
            use oauth2::{AuthUrl, ClientId, ClientSecret, RefreshToken, TokenUrl};
            use oauth2::basic::BasicClient;
            use oauth2::TokenResponse as _;

            let client_id = ClientId::new(config.client_id.ok_or_else(|| anyhow::anyhow!("missing client_id"))?);
            let client_secret = ClientSecret::new(config.client_secret.ok_or_else(|| anyhow::anyhow!("missing client_secret"))?);
            let auth_url = AuthUrl::new(config.auth_url.ok_or_else(|| anyhow::anyhow!("missing auth_url"))?)?;
            let token_url = TokenUrl::new(config.token_url.ok_or_else(|| anyhow::anyhow!("missing token_url"))?)?;

            let client = apply_oauth2_auth_type(
                provider_key,
                BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url)),
            );
            let token_resp = client
                .exchange_refresh_token(&RefreshToken::new(refresh_token))
                .request_async(async_http_client)
                .await?;

            let access_token = token_resp.access_token().secret().to_string();
            let new_refresh_token = token_resp.refresh_token().map(|t: &oauth2::RefreshToken| t.secret().to_string());
            let expires_at = token_resp.expires_in().map(|d: std::time::Duration| {
                let dt = time::OffsetDateTime::now_utc() + d;
                dt.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| dt.to_string())
            });
            let new_scopes = token_resp.scopes().map(|s| {
                s.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ")
            });

            state.accounts.update_identity_tokens(provider_key, subject, &access_token, new_refresh_token.as_deref(), expires_at.as_deref(), new_scopes.as_deref()).await?;
        }
    }

    Ok(())
}

// Use openidconnect's built-in reqwest async client function directly
use openidconnect::reqwest::async_http_client;

fn apply_oauth2_auth_type(
    provider_key: &str,
    client: oauth2::basic::BasicClient,
) -> oauth2::basic::BasicClient {
    if provider_key == "linkedin" {
        client.set_auth_type(oauth2::AuthType::RequestBody)
    } else {
        client
    }
}
