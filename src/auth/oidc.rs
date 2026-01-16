use axum::response::{IntoResponse, Redirect};
use tower_cookies::Cookies;
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
                return Redirect::temporary("/login").into_response();
            }
        }
    }

    // Placeholder behavior
    if let Some(sess) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(link_provider) = account::get_link_cookie(&cookies) {
            if link_provider == provider_key {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let sub = format!("{}-placeholder-sub", provider_key);
                let new_identity = NewIdentity { 
                    id: &identity_id, 
                    user_id: &sess.user_id, 
                    provider_key, 
                    subject: &sub, 
                    email: Some(&format!("{}@example.com", provider_key)), 
                    claims: None 
                };
                if let Err(e) = state.accounts.link_identity(new_identity).await {
                    tracing::error!(provider=%provider_key, error=?e, "failed to link identity (placeholder)");
                }
                account::clear_link_cookie(&cookies);
                return Redirect::temporary("/account").into_response();
            }
        }
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    session::set_session(&cookies, &state.cookie_key, &user_id, 60);
    Redirect::temporary("/").into_response()
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

    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

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
    let redirect_url = RedirectUrl::new(redirect_uri)?;
    
    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(redirect_url);

    let token_resp = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(tmp.pkce_verifier))
        .request_async(async_http_client)
        .await?;

    let id_token = token_resp.id_token().ok_or_else(|| anyhow::anyhow!("missing id_token"))?;
    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    let claims: CoreIdTokenClaims = id_token.claims(&id_token_verifier, &Nonce::new(tmp.nonce))?.clone();

    let sub = claims.subject().as_str().to_string();
    let email: Option<String> = claims.email().map(|e| e.to_string());
    let name: Option<String> = claims.name().and_then(|n| n.get(None)).map(|v| v.to_string());

    if let Some(current) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(link_provider) = account::get_link_cookie(&cookies) {
            if link_provider == provider_key {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let new_identity = NewIdentity { id: &identity_id, user_id: &current.user_id, provider_key, subject: &sub, email: email.as_deref(), claims: None };
                state.accounts.link_identity(new_identity).await?;
                account::clear_link_cookie(&cookies);
                return Ok(Redirect::temporary("/account").into_response());
            }
        }
    }

    if let Some(user) = state.accounts.find_user_by_identity(provider_key, &sub).await? {
        session::set_session(&cookies, &state.cookie_key, &user.id, 60);
        return Ok(Redirect::temporary("/").into_response());
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    let identity_id = uuid::Uuid::new_v4().to_string();
    let new_user = crate::models::user::NewUser { id: &user_id, primary_email: email.as_deref(), display_name: name.as_deref() };
    let new_identity = NewIdentity { id: &identity_id, user_id: &user_id, provider_key, subject: &sub, email: email.as_deref(), claims: None };
    let user = state.accounts.create_user_and_link(new_user, new_identity).await?;
    session::set_session(&cookies, &state.cookie_key, &user.id, 60);
    Ok(Redirect::temporary("/").into_response())
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

    let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(redirect_url);

    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("user:email".to_string()))
        .add_scope(Scope::new("read:user".to_string()))
        .url();

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
    let redirect_url = RedirectUrl::new(redirect_uri)?;

    let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(redirect_url);

    let token_resp = client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await?;

    let access_token = token_resp.access_token().secret();

    // Provider specific user info fetching (GitHub example)
    if provider_key == "github" {
        return fetch_github_user_and_login(state, cookies, access_token).await;
    }

    Err(anyhow::anyhow!("unsupported oauth2 provider: {}", provider_key))
}

async fn fetch_github_user_and_login(state: &AppState, cookies: Cookies, access_token: &str) -> anyhow::Result<axum::response::Response> {
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
        if let Some(link_provider) = account::get_link_cookie(&cookies) {
            if link_provider == "github" {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let new_identity = NewIdentity { id: &identity_id, user_id: &current.user_id, provider_key: "github", subject: &sub, email: email.as_deref(), claims: None };
                state.accounts.link_identity(new_identity).await?;
                account::clear_link_cookie(&cookies);
                return Ok(Redirect::temporary("/account").into_response());
            }
        }
    }

    if let Some(user) = state.accounts.find_user_by_identity("github", &sub).await? {
        session::set_session(&cookies, &state.cookie_key, &user.id, 60);
        return Ok(Redirect::temporary("/").into_response());
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    let identity_id = uuid::Uuid::new_v4().to_string();
    let new_user = crate::models::user::NewUser { id: &user_id, primary_email: email.as_deref(), display_name: name.as_deref() };
    let new_identity = NewIdentity { id: &identity_id, user_id: &user_id, provider_key: "github", subject: &sub, email: email.as_deref(), claims: None };
    let user = state.accounts.create_user_and_link(new_user, new_identity).await?;
    session::set_session(&cookies, &state.cookie_key, &user.id, 60);
    Ok(Redirect::temporary("/").into_response())
}

// Use openidconnect's built-in reqwest async client function directly
use openidconnect::reqwest::async_http_client;

fn rand_string(len: usize) -> String {
    use rand::{distributions::Alphanumeric, Rng};
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}
