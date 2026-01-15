use axum::response::{IntoResponse, Redirect};
use tower_cookies::Cookies;

use crate::{app::AppState, auth::session, models::identity::NewIdentity, web::handlers::account};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcMode {
    Placeholder,
    Live,
}

#[derive(Debug, Clone)]
pub struct OidcSettings {
    pub google_mode: OidcMode,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub google_issuer: String,
    pub redirect_path_google: String,
    pub github_mode: OidcMode,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub redirect_path_github: String,
    pub dex_mode: OidcMode,
    pub dex_client_id: Option<String>,
    pub dex_client_secret: Option<String>,
    pub dex_issuer: String,
    pub redirect_path_dex: String,
    pub public_base_url: String,
}

impl OidcSettings {
    pub fn from_config(cfg: &crate::config::AppConfig) -> anyhow::Result<Self> {
        let google_mode = match std::env::var("AUTH_GOOGLE_MODE").unwrap_or_else(|_| "placeholder".into()).to_lowercase().as_str() {
            "live" => OidcMode::Live,
            _ => OidcMode::Placeholder,
        };
        let google_client_id = std::env::var("GOOGLE_CLIENT_ID").ok();
        let google_client_secret = std::env::var("GOOGLE_CLIENT_SECRET").ok();
        let google_issuer = std::env::var("GOOGLE_ISSUER").unwrap_or_else(|_| "https://accounts.google.com".into());
        let redirect_path_google = "/auth/callback/google".to_string();

        let github_mode = match std::env::var("AUTH_GITHUB_MODE").unwrap_or_else(|_| "placeholder".into()).to_lowercase().as_str() {
            "live" => OidcMode::Live,
            _ => OidcMode::Placeholder,
        };
        let github_client_id = std::env::var("GITHUB_CLIENT_ID").ok();
        let github_client_secret = std::env::var("GITHUB_CLIENT_SECRET").ok();
        let redirect_path_github = "/auth/callback/github".to_string();

        let dex_mode = match std::env::var("AUTH_DEX_MODE").unwrap_or_else(|_| "placeholder".into()).to_lowercase().as_str() {
            "live" => OidcMode::Live,
            _ => OidcMode::Placeholder,
        };
        let dex_client_id = std::env::var("DEX_CLIENT_ID").ok();
        let dex_client_secret = std::env::var("DEX_CLIENT_SECRET").ok();
        let dex_issuer = std::env::var("DEX_ISSUER").unwrap_or_else(|_| "http://localhost:5556/dex".into());
        let redirect_path_dex = "/auth/callback/dex".to_string();

        let public_base_url = cfg.server.public_url.clone();
        Ok(Self {
            google_mode,
            google_client_id,
            google_client_secret,
            google_issuer,
            redirect_path_google,
            github_mode,
            github_client_id,
            github_client_secret,
            redirect_path_github,
            dex_mode,
            dex_client_id,
            dex_client_secret,
            dex_issuer,
            redirect_path_dex,
            public_base_url,
        })
    }

    pub fn google_redirect_url(&self) -> String {
        format!("{}{}", self.public_base_url.trim_end_matches('/'), self.redirect_path_google)
    }

    pub fn github_redirect_url(&self) -> String {
        format!("{}{}", self.public_base_url.trim_end_matches('/'), self.redirect_path_github)
    }

    pub fn dex_redirect_url(&self) -> String {
        format!("{}{}", self.public_base_url.trim_end_matches('/'), self.redirect_path_dex)
    }
}

// Placeholder OIDC start for Google: in a full implementation this would
// construct an authorization request URL (state, nonce, PKCE) and redirect
// to Google's authorization endpoint. For now we just bounce back.
pub async fn start_google(state: &AppState, cookies: Cookies) -> impl IntoResponse {
    match state.oidc.google_mode {
        OidcMode::Placeholder => {
            // Placeholder: jump straight to callback to simulate a successful auth flow
            Redirect::temporary("/auth/callback/google").into_response()
        }
        OidcMode::Live => {
            match start_google_live(state, cookies).await {
                Ok(r) => r.into_response(),
                Err(e) => {
                    tracing::error!(error=?e, "google start failed; falling back to login");
                    Redirect::temporary("/login").into_response()
                }
            }
        }
    }
}

// Placeholder OIDC callback for Google: in a full implementation this would
// verify the state, exchange the authorization code for tokens, validate the
// ID token, look up or create the user, and then issue a session cookie.
// For scaffolding we just create a temporary dev session and redirect home.
pub async fn callback_google(state: &AppState, cookies: Cookies, q: crate::web::handlers::auth::AuthCallbackQuery) -> impl IntoResponse {
    if matches!(state.oidc.google_mode, OidcMode::Live) {
        match callback_google_live(state, cookies, q).await {
            Ok(resp) => return resp,
            Err(e) => {
                tracing::error!(error=?e, "google callback failed; redirecting to /login");
                return Redirect::temporary("/login").into_response();
            }
        }
    }
    // Placeholder behavior:
    // - If user is already logged in and is in "link" mode (cookie set), create a new identity link
    //   with a placeholder subject and redirect to /account.
    // - Otherwise, create a dev session with a random user id and redirect home.

    if let Some(sess) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(provider) = account::get_link_cookie(&cookies) {
            let identity_id = uuid::Uuid::new_v4();
            let subject = uuid::Uuid::new_v4(); // placeholder until real OIDC is wired
            // Build owned strings to satisfy lifetimes of Insertable refs
            let id_s = identity_id.to_string();
            let sub_s = subject.to_string();
            let new_identity = NewIdentity {
                id: &id_s,
                user_id: &sess.user_id,
                provider_key: &provider,
                subject: &sub_s,
                email: None,
                claims: None,
            };
            if let Err(e) = state.accounts.link_identity(new_identity).await {
                tracing::error!(error=?e, "failed to link identity (placeholder)");
            }
            account::clear_link_cookie(&cookies);
            return Redirect::temporary("/account").into_response();
        }
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    session::set_session(&cookies, &state.cookie_key, &user_id, 60); // 60 minutes
    Redirect::temporary("/").into_response()
}

// ===== Live Google OIDC implementation =====

const GOOGLE_TMP_COOKIE: &str = "g_oidc_tmp";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TmpAuthState {
    state: String,
    nonce: String,
    pkce_verifier: String,
}

fn write_tmp_state(cookies: &Cookies, key: &tower_cookies::Key, v: &TmpAuthState) -> anyhow::Result<()> {
    let payload = serde_json::to_string(v)?;
    let mut c = tower_cookies::Cookie::new(GOOGLE_TMP_COOKIE, payload);
    c.set_path("/");
    c.set_http_only(true);
    c.set_same_site(tower_cookies::cookie::SameSite::Lax);
    c.set_secure(session::is_https());
    // short TTL; browser will treat session cookie unless Max-Age set. That's fine for dev.
    cookies.private(key).add(c);
    Ok(())
}

fn take_tmp_state(cookies: &Cookies, key: &tower_cookies::Key) -> anyhow::Result<Option<TmpAuthState>> {
    if let Some(c) = cookies.private(key).get(GOOGLE_TMP_COOKIE) {
        let v: TmpAuthState = serde_json::from_str(c.value())?;
        // remove to prevent replay
        cookies.private(key).remove(c);
        return Ok(Some(v));
    }
    Ok(None)
}

async fn start_google_live(state: &AppState, cookies: Cookies) -> anyhow::Result<Redirect> {
    use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
    use openidconnect::{AuthenticationFlow, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope};

    let issuer = IssuerUrl::new(state.oidc.google_issuer.clone())?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client).await?;

    let client_id = ClientId::new(state.oidc.google_client_id.clone().ok_or_else(|| anyhow::anyhow!("missing GOOGLE_CLIENT_ID"))?);
    let client_secret = ClientSecret::new(state.oidc.google_client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing GOOGLE_CLIENT_SECRET"))?);
    let redirect_url = RedirectUrl::new(state.oidc.google_redirect_url())?;

    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(redirect_url);

    // PKCE
    let pkce_verifier = PkceCodeVerifier::new(rand_string(128));
    let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);

    // Auth request
    let (auth_url, csrf_state, nonce) = client
        .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .set_pkce_challenge(pkce_challenge)
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .url();

    // Persist tmp state
    let tmp = TmpAuthState { state: csrf_state.secret().to_string(), nonce: nonce.secret().to_string(), pkce_verifier: pkce_verifier.secret().to_string() };
    write_tmp_state(&cookies, &state.cookie_key, &tmp)?;

    Ok(Redirect::temporary(auth_url.as_str()))
}

async fn callback_google_live(state: &AppState, cookies: Cookies, q: crate::web::handlers::auth::AuthCallbackQuery) -> anyhow::Result<axum::response::Response> {
    use openidconnect::core::{CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata};
    use openidconnect::{AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl, TokenResponse};

    if let Some(err) = q.error {
        return Err(anyhow::anyhow!("provider_error: {}", err));
    }
    let code = q.code.ok_or_else(|| anyhow::anyhow!("missing code"))?;
    let state_param = q.state.ok_or_else(|| anyhow::anyhow!("missing state"))?;

    let tmp = take_tmp_state(&cookies, &state.cookie_key)?.ok_or_else(|| anyhow::anyhow!("missing stored auth state"))?;
    if tmp.state != state_param { return Err(anyhow::anyhow!("state mismatch")); }

    // Recreate client
    let issuer = IssuerUrl::new(state.oidc.google_issuer.clone())?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client).await?;
    let client_id = ClientId::new(state.oidc.google_client_id.clone().ok_or_else(|| anyhow::anyhow!("missing GOOGLE_CLIENT_ID"))?);
    let client_secret = ClientSecret::new(state.oidc.google_client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing GOOGLE_CLIENT_SECRET"))?);
    let redirect_url = RedirectUrl::new(state.oidc.google_redirect_url())?;
    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(redirect_url);

    // Exchange code
    let token_resp = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(tmp.pkce_verifier))
        .request_async(async_http_client)
        .await?;

    // Validate ID token
    let id_token = token_resp.id_token().ok_or_else(|| anyhow::anyhow!("missing id_token"))?;
    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    let claims: CoreIdTokenClaims = id_token.claims(&id_token_verifier, &Nonce::new(tmp.nonce))?.clone();

    let sub = claims.subject().as_str().to_string();
    let email: Option<String> = claims.email().map(|e| e.to_string());
    let name: Option<String> = claims.name().and_then(|n| n.get(None)).map(|v| v.to_string());

    // Link vs login
    if let Some(current) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(provider) = account::get_link_cookie(&cookies) {
            if provider == "google" {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let new_identity = NewIdentity { id: &identity_id, user_id: &current.user_id, provider_key: "google", subject: &sub, email: email.as_deref(), claims: None };
                state.accounts.link_identity(new_identity).await?;
                account::clear_link_cookie(&cookies);
                return Ok(Redirect::temporary("/account").into_response());
            }
        }
    }

    // Login or signup
    if let Some(user) = state.accounts.find_user_by_identity("google", &sub).await? {
        session::set_session(&cookies, &state.cookie_key, &user.id, 60);
        return Ok(Redirect::temporary("/").into_response());
    }

    // Create user + identity
    let user_id = uuid::Uuid::new_v4().to_string();
    let identity_id = uuid::Uuid::new_v4().to_string();
    let new_user = crate::models::user::NewUser { id: &user_id, primary_email: email.as_deref(), display_name: name.as_deref() };
    let new_identity = NewIdentity { id: &identity_id, user_id: &user_id, provider_key: "google", subject: &sub, email: email.as_deref(), claims: None };
    let user = state.accounts.create_user_and_link(new_user, new_identity).await?;
    session::set_session(&cookies, &state.cookie_key, &user.id, 60);
    Ok(Redirect::temporary("/").into_response())
}

// ===== Dex OIDC implementation =====

const DEX_TMP_COOKIE: &str = "dex_oidc_tmp";

fn write_tmp_state_dex(cookies: &Cookies, key: &tower_cookies::Key, v: &TmpAuthState) -> anyhow::Result<()> {
    let payload = serde_json::to_string(v)?;
    let mut c = tower_cookies::Cookie::new(DEX_TMP_COOKIE, payload);
    c.set_path("/");
    c.set_http_only(true);
    c.set_same_site(tower_cookies::cookie::SameSite::Lax);
    c.set_secure(session::is_https());
    cookies.private(key).add(c);
    Ok(())
}

fn take_tmp_state_dex(cookies: &Cookies, key: &tower_cookies::Key) -> anyhow::Result<Option<TmpAuthState>> {
    if let Some(c) = cookies.private(key).get(DEX_TMP_COOKIE) {
        let v: TmpAuthState = serde_json::from_str(c.value())?;
        cookies.private(key).remove(c);
        return Ok(Some(v));
    }
    Ok(None)
}

pub async fn start_dex(state: &AppState, cookies: Cookies) -> impl IntoResponse {
    match state.oidc.dex_mode {
        OidcMode::Placeholder => {
            Redirect::temporary("/auth/callback/dex").into_response()
        }
        OidcMode::Live => {
            match start_dex_live(state, cookies).await {
                Ok(r) => r.into_response(),
                Err(e) => {
                    tracing::error!(error=?e, "dex start failed; falling back to login");
                    Redirect::temporary("/login").into_response()
                }
            }
        }
    }
}

pub async fn callback_dex(state: &AppState, cookies: Cookies, q: crate::web::handlers::auth::AuthCallbackQuery) -> impl IntoResponse {
    if matches!(state.oidc.dex_mode, OidcMode::Live) {
        match callback_dex_live(state, cookies, q).await {
            Ok(resp) => return resp,
            Err(e) => {
                tracing::error!(error=?e, "dex callback failed; redirecting to /login");
                return Redirect::temporary("/login").into_response();
            }
        }
    }
    // Placeholder logic for dex (similar to google)
    if let Some(sess) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(provider) = account::get_link_cookie(&cookies) {
            if provider == "dex" {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let sub = "dex-subject-123";
                let new_identity = NewIdentity { id: &identity_id, user_id: &sess.user_id, provider_key: "dex", subject: sub, email: Some("dex@example.com"), claims: None };
                if let Err(e) = state.accounts.link_identity(new_identity).await {
                    tracing::error!(error=?e, "failed to link identity (dex placeholder)");
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

async fn start_dex_live(state: &AppState, cookies: Cookies) -> anyhow::Result<Redirect> {
    use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
    use openidconnect::{AuthenticationFlow, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope};

    let issuer = IssuerUrl::new(state.oidc.dex_issuer.clone())?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client).await?;

    let client_id = ClientId::new(state.oidc.dex_client_id.clone().ok_or_else(|| anyhow::anyhow!("missing DEX_CLIENT_ID"))?);
    let client_secret = ClientSecret::new(state.oidc.dex_client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing DEX_CLIENT_SECRET"))?);
    let redirect_url = RedirectUrl::new(state.oidc.dex_redirect_url())?;

    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(redirect_url);

    let pkce_verifier = PkceCodeVerifier::new(rand_string(128));
    let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);

    let (auth_url, csrf_state, nonce) = client
        .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .set_pkce_challenge(pkce_challenge)
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .url();

    let tmp = TmpAuthState { state: csrf_state.secret().to_string(), nonce: nonce.secret().to_string(), pkce_verifier: pkce_verifier.secret().to_string() };
    write_tmp_state_dex(&cookies, &state.cookie_key, &tmp)?;

    Ok(Redirect::temporary(auth_url.as_str()))
}

async fn callback_dex_live(state: &AppState, cookies: Cookies, q: crate::web::handlers::auth::AuthCallbackQuery) -> anyhow::Result<axum::response::Response> {
    use openidconnect::core::{CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata};
    use openidconnect::{AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl, TokenResponse};

    if let Some(err) = q.error {
        return Err(anyhow::anyhow!("provider_error: {}", err));
    }
    let code = q.code.ok_or_else(|| anyhow::anyhow!("missing code"))?;
    let state_param = q.state.ok_or_else(|| anyhow::anyhow!("missing state"))?;

    let tmp = take_tmp_state_dex(&cookies, &state.cookie_key)?.ok_or_else(|| anyhow::anyhow!("missing stored auth state"))?;
    if tmp.state != state_param { return Err(anyhow::anyhow!("state mismatch")); }

    let issuer = IssuerUrl::new(state.oidc.dex_issuer.clone())?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client).await?;
    let client_id = ClientId::new(state.oidc.dex_client_id.clone().ok_or_else(|| anyhow::anyhow!("missing DEX_CLIENT_ID"))?);
    let client_secret = ClientSecret::new(state.oidc.dex_client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing DEX_CLIENT_SECRET"))?);
    let redirect_url = RedirectUrl::new(state.oidc.dex_redirect_url())?;
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
        if let Some(provider) = account::get_link_cookie(&cookies) {
            if provider == "dex" {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let new_identity = NewIdentity { id: &identity_id, user_id: &current.user_id, provider_key: "dex", subject: &sub, email: email.as_deref(), claims: None };
                state.accounts.link_identity(new_identity).await?;
                account::clear_link_cookie(&cookies);
                return Ok(Redirect::temporary("/account").into_response());
            }
        }
    }

    if let Some(user) = state.accounts.find_user_by_identity("dex", &sub).await? {
        session::set_session(&cookies, &state.cookie_key, &user.id, 60);
        return Ok(Redirect::temporary("/").into_response());
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    let identity_id = uuid::Uuid::new_v4().to_string();
    let new_user = crate::models::user::NewUser { id: &user_id, primary_email: email.as_deref(), display_name: name.as_deref() };
    let new_identity = NewIdentity { id: &identity_id, user_id: &user_id, provider_key: "dex", subject: &sub, email: email.as_deref(), claims: None };
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

// ===== GitHub OAuth2 implementation =====

const GITHUB_TMP_COOKIE: &str = "gh_oauth_tmp";

pub async fn start_github(state: &AppState, cookies: Cookies) -> impl IntoResponse {
    match state.oidc.github_mode {
        OidcMode::Placeholder => {
            Redirect::temporary("/auth/callback/github").into_response()
        }
        OidcMode::Live => {
            match start_github_live(state, cookies).await {
                Ok(r) => r.into_response(),
                Err(e) => {
                    tracing::error!(error=?e, "github start failed; falling back to login");
                    Redirect::temporary("/login").into_response()
                }
            }
        }
    }
}

pub async fn callback_github(state: &AppState, cookies: Cookies, q: crate::web::handlers::auth::AuthCallbackQuery) -> impl IntoResponse {
    if matches!(state.oidc.github_mode, OidcMode::Live) {
        match callback_github_live(state, cookies, q).await {
            Ok(resp) => return resp,
            Err(e) => {
                tracing::error!(error=?e, "github callback failed; redirecting to /login");
                return Redirect::temporary("/login").into_response();
            }
        }
    }

    // Placeholder behavior - same as Google
    if let Some(sess) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(provider) = account::get_link_cookie(&cookies) {
            let identity_id = uuid::Uuid::new_v4();
            let subject = uuid::Uuid::new_v4();
            let id_s = identity_id.to_string();
            let sub_s = subject.to_string();
            let new_identity = NewIdentity {
                id: &id_s,
                user_id: &sess.user_id,
                provider_key: &provider,
                subject: &sub_s,
                email: None,
                claims: None,
            };
            if let Err(e) = state.accounts.link_identity(new_identity).await {
                tracing::error!(error=?e, "failed to link identity (placeholder)");
            }
            account::clear_link_cookie(&cookies);
            return Redirect::temporary("/account").into_response();
        }
    }

    let user_id = uuid::Uuid::new_v4().to_string();
    session::set_session(&cookies, &state.cookie_key, &user_id, 60);
    Redirect::temporary("/").into_response()
}

async fn start_github_live(state: &AppState, cookies: Cookies) -> anyhow::Result<Redirect> {
    use oauth2::{AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, TokenUrl, Scope};
    use oauth2::basic::BasicClient;

    let client_id = ClientId::new(state.oidc.github_client_id.clone().ok_or_else(|| anyhow::anyhow!("missing GITHUB_CLIENT_ID"))?);
    let client_secret = ClientSecret::new(state.oidc.github_client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing GITHUB_CLIENT_SECRET"))?);
    let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())?;
    let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())?;
    let redirect_url = RedirectUrl::new(state.oidc.github_redirect_url())?;

    let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(redirect_url);

    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("user:email".to_string()))
        .add_scope(Scope::new("read:user".to_string()))
        .url();

    // Store state in cookie
    let tmp = TmpAuthState {
        state: csrf_state.secret().to_string(),
        nonce: String::new(), // GitHub doesn't use nonce
        pkce_verifier: String::new(), // Not using PKCE for now
    };
    write_tmp_state_github(&cookies, &state.cookie_key, &tmp)?;

    Ok(Redirect::temporary(auth_url.as_str()))
}

async fn callback_github_live(state: &AppState, cookies: Cookies, q: crate::web::handlers::auth::AuthCallbackQuery) -> anyhow::Result<axum::response::Response> {
    use oauth2::{AuthUrl, ClientId, ClientSecret, AuthorizationCode, RedirectUrl, TokenUrl};
    use oauth2::basic::BasicClient;
    use oauth2::reqwest::async_http_client;
    use oauth2::TokenResponse;

    if let Some(err) = q.error {
        return Err(anyhow::anyhow!("provider_error: {}", err));
    }
    let code = q.code.ok_or_else(|| anyhow::anyhow!("missing code"))?;
    let state_param = q.state.ok_or_else(|| anyhow::anyhow!("missing state"))?;

    let tmp = take_tmp_state_github(&cookies, &state.cookie_key)?.ok_or_else(|| anyhow::anyhow!("missing stored auth state"))?;
    if tmp.state != state_param {
        return Err(anyhow::anyhow!("state mismatch"));
    }

    // Recreate client
    let client_id = ClientId::new(state.oidc.github_client_id.clone().ok_or_else(|| anyhow::anyhow!("missing GITHUB_CLIENT_ID"))?);
    let client_secret = ClientSecret::new(state.oidc.github_client_secret.clone().ok_or_else(|| anyhow::anyhow!("missing GITHUB_CLIENT_SECRET"))?);
    let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())?;
    let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())?;
    let redirect_url = RedirectUrl::new(state.oidc.github_redirect_url())?;

    let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(redirect_url);

    // Exchange code for token
    let token_resp = client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await?;

    let access_token = token_resp.access_token().secret();

    // Fetch user info from GitHub API
    let user_info: serde_json::Value = reqwest::Client::new()
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("User-Agent", "oauth3-rust-app")
        .send()
        .await?
        .json()
        .await?;

    let sub = user_info["id"].as_i64().ok_or_else(|| anyhow::anyhow!("missing user id"))?.to_string();
    let email = user_info["email"].as_str().map(|s| s.to_string());
    let name = user_info["name"].as_str().or(user_info["login"].as_str()).map(|s| s.to_string());

    // Link vs login (same logic as Google)
    if let Some(current) = session::get_session(&cookies, &state.cookie_key) {
        if let Some(provider) = account::get_link_cookie(&cookies) {
            if provider == "github" {
                let identity_id = uuid::Uuid::new_v4().to_string();
                let new_identity = NewIdentity {
                    id: &identity_id,
                    user_id: &current.user_id,
                    provider_key: "github",
                    subject: &sub,
                    email: email.as_deref(),
                    claims: None,
                };
                state.accounts.link_identity(new_identity).await?;
                account::clear_link_cookie(&cookies);
                return Ok(Redirect::temporary("/account").into_response());
            }
        }
    }

    // Login or signup
    if let Some(user) = state.accounts.find_user_by_identity("github", &sub).await? {
        session::set_session(&cookies, &state.cookie_key, &user.id, 60);
        return Ok(Redirect::temporary("/").into_response());
    }

    // Create user + identity
    let user_id = uuid::Uuid::new_v4().to_string();
    let identity_id = uuid::Uuid::new_v4().to_string();
    let new_user = crate::models::user::NewUser {
        id: &user_id,
        primary_email: email.as_deref(),
        display_name: name.as_deref(),
    };
    let new_identity = NewIdentity {
        id: &identity_id,
        user_id: &user_id,
        provider_key: "github",
        subject: &sub,
        email: email.as_deref(),
        claims: None,
    };
    let user = state.accounts.create_user_and_link(new_user, new_identity).await?;
    session::set_session(&cookies, &state.cookie_key, &user.id, 60);
    Ok(Redirect::temporary("/").into_response())
}

fn write_tmp_state_github(cookies: &Cookies, key: &tower_cookies::Key, v: &TmpAuthState) -> anyhow::Result<()> {
    let payload = serde_json::to_string(v)?;
    let mut c = tower_cookies::Cookie::new(GITHUB_TMP_COOKIE, payload);
    c.set_path("/");
    c.set_http_only(true);
    c.set_same_site(tower_cookies::cookie::SameSite::Lax);
    c.set_secure(session::is_https());
    cookies.private(key).add(c);
    Ok(())
}

fn take_tmp_state_github(cookies: &Cookies, key: &tower_cookies::Key) -> anyhow::Result<Option<TmpAuthState>> {
    if let Some(c) = cookies.private(key).get(GITHUB_TMP_COOKIE) {
        let v: TmpAuthState = serde_json::from_str(c.value())?;
        cookies.private(key).remove(c);
        return Ok(Some(v));
    }
    Ok(None)
}
