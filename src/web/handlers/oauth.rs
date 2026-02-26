use axum::{
    extract::{Form, OriginalUri, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::Engine as _;
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use std::collections::{BTreeSet, HashSet};
use time::{Duration, OffsetDateTime};
use tower_cookies::Cookies;
use url::Url;

use crate::{
    app::AppState,
    auth::session,
    models::{
        app_token::{AppAccessToken, AppRefreshToken},
        consent::UserConsent,
        oauth_code::OAuthCode,
    },
};

const AUTH_CODE_TTL_MINUTES: i64 = 10;
const ACCESS_TOKEN_TTL_MINUTES: i64 = 10;
const REFRESH_TOKEN_TTL_DAYS: i64 = 30;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeForm {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub decision: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
}

pub async fn authorize_get(
    State(state): State<AppState>,
    cookies: Cookies,
    OriginalUri(uri): OriginalUri,
    Query(q): Query<AuthorizeQuery>,
) -> impl IntoResponse {
    let Some(sess) = session::get_session(&cookies, &state.cookie_key) else {
        let return_to = uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/oauth/authorize".to_string());
        session::set_login_return_to(&cookies, &return_to);
        return Redirect::temporary("/login").into_response();
    };

    let ctx = match build_authorize_context(&state, &q).await {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };

    let consent = match state
        .accounts
        .get_user_consent(&sess.user_id, &ctx.client_id)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error=?e, "failed to load consent");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if let Some(consent) = consent {
        if consent.revoked_at.is_none() && scopes_allow(&consent.scopes, &ctx.scopes) {
            return match issue_auth_code(&state, &sess.user_id, &ctx).await {
                Ok(code) => build_redirect_response(&ctx.redirect_uri, vec![
                    ("code".to_string(), code),
                    ("state".to_string(), ctx.state.clone().unwrap_or_default()),
                ]),
                Err(resp) => resp,
            };
        }
    }

    Html(render_consent_page(&ctx)).into_response()
}

pub async fn authorize_post(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<AuthorizeForm>,
) -> impl IntoResponse {
    let Some(sess) = session::get_session(&cookies, &state.cookie_key) else {
        session::set_login_return_to(&cookies, "/oauth/authorize");
        return Redirect::temporary("/login").into_response();
    };

    let q = AuthorizeQuery {
        response_type: form.response_type.clone(),
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        scope: form.scope.clone(),
        state: form.state.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: form.code_challenge_method.clone(),
    };

    let ctx = match build_authorize_context(&state, &q).await {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };

    if form.decision != "approve" {
        return oauth_error_response(Some(&ctx.redirect_uri), "access_denied", ctx.state.as_deref());
    }

    let consent = UserConsent {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: sess.user_id.clone(),
        app_id: ctx.client_id.clone(),
        scopes: ctx.scope_string.clone(),
        created_at: OffsetDateTime::now_utc().to_string(),
        revoked_at: None,
    };

    if let Err(e) = state.accounts.save_user_consent(consent).await {
        tracing::error!(error=?e, "failed to save consent");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    match issue_auth_code(&state, &sess.user_id, &ctx).await {
        Ok(code) => build_redirect_response(&ctx.redirect_uri, vec![
            ("code".to_string(), code),
            ("state".to_string(), ctx.state.clone().unwrap_or_default()),
        ]),
        Err(resp) => resp,
    }
}

pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    let (app, _client_id) = match authenticate_client(&state, &headers, req.client_id.as_deref(), req.client_secret.as_deref()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    match req.grant_type.as_str() {
        "authorization_code" => {
            let Some(code) = req.code else {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_request");
            };
            let Some(redirect_uri) = req.redirect_uri else {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_request");
            };

            let code_hash = hash_token(&code);
            let code_row = match state.accounts.consume_oauth_code(&code_hash).await {
                Ok(row) => row,
                Err(e) => {
                    tracing::error!(error=?e, "failed to consume auth code");
                    return token_error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
                }
            };
            let Some(code_row) = code_row else {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
            };

            if code_row.app_id != app.id || redirect_uri != code_row.redirect_uri {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
            }

            if is_expired(&code_row.expires_at) {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
            }

            if let Some(challenge) = code_row.code_challenge.as_deref() {
                let verifier = req.code_verifier.as_deref().unwrap_or("");
                if !verify_pkce(challenge, code_row.code_challenge_method.as_deref(), verifier) {
                    return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
                }
            } else if app.client_type.eq_ignore_ascii_case("public") {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
            }

            if !consent_allows(&state, &code_row.user_id, &app.id, &code_row.scopes).await {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
            }

            let (access_token, refresh_token, expires_in) = match issue_tokens(&state, &app.id, &code_row.user_id, &code_row.scopes, None).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };

            Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in,
                refresh_token: Some(refresh_token),
                scope: code_row.scopes,
            })
            .into_response()
        }
        "refresh_token" => {
            let Some(refresh_token) = req.refresh_token else {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_request");
            };

            let token_hash = hash_token(&refresh_token);
            let refresh_row = match state.accounts.get_app_refresh_token_by_hash(&token_hash).await {
                Ok(row) => row,
                Err(e) => {
                    tracing::error!(error=?e, "failed to load refresh token");
                    return token_error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
                }
            };
            let Some(refresh_row) = refresh_row else {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
            };

            if refresh_row.app_id != app.id {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
            }

            if is_expired(&refresh_row.expires_at) {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
            }

            if !consent_allows(&state, &refresh_row.user_id, &app.id, &refresh_row.scopes).await {
                return token_error_response(StatusCode::BAD_REQUEST, "invalid_grant");
            }

            let (access_token, new_refresh_token, expires_in) = match issue_tokens(&state, &app.id, &refresh_row.user_id, &refresh_row.scopes, Some(&refresh_row.id)).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };

            Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in,
                refresh_token: Some(new_refresh_token),
                scope: refresh_row.scopes,
            })
            .into_response()
        }
        _ => token_error_response(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<RevokeRequest>,
) -> impl IntoResponse {
    let (app, _) = match authenticate_client(&state, &headers, req.client_id.as_deref(), req.client_secret.as_deref()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let token_hash = hash_token(&req.token);
    if let Ok(Some(access)) = state.accounts.get_app_access_token_by_hash(&token_hash).await {
        if access.app_id == app.id {
            let _ = state.accounts.revoke_app_access_token(&access.id).await;
        }
        return StatusCode::OK.into_response();
    }

    if let Ok(Some(refresh)) = state.accounts.get_app_refresh_token_by_hash(&token_hash).await {
        if refresh.app_id == app.id {
            let _ = state.accounts.revoke_app_refresh_token(&refresh.id, None).await;
        }
    }

    StatusCode::OK.into_response()
}

struct AuthorizeContext {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    scope_string: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    app_name: String,
}

async fn build_authorize_context(state: &AppState, q: &AuthorizeQuery) -> Result<AuthorizeContext, Response> {
    if q.response_type != "code" {
        return Err(oauth_error_response(None, "unsupported_response_type", q.state.as_deref()));
    }

    let app = match state.accounts.get_application(&q.client_id).await {
        Ok(Some(app)) => app,
        Ok(None) => return Err(oauth_error_response(None, "unauthorized_client", q.state.as_deref())),
        Err(e) => {
            tracing::error!(error=?e, "failed to load application");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    if app.is_enabled != 1 {
        return Err(oauth_error_response(None, "unauthorized_client", q.state.as_deref()));
    }

    let redirect_uris = match state.accounts.list_app_redirect_uris(&app.id).await {
        Ok(list) => list,
        Err(e) => {
            tracing::error!(error=?e, "failed to list redirect uris");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    if !redirect_uri_allowed(&redirect_uris, &q.redirect_uri) {
        return Err(oauth_error_response(None, "invalid_request", q.state.as_deref()));
    }

    let allowed_scopes = normalize_scopes(Some(&app.allowed_scopes));
    let mut requested_scopes = normalize_scopes(q.scope.as_deref());
    if requested_scopes.is_empty() {
        requested_scopes = allowed_scopes.clone();
    }
    if !scopes_within(&requested_scopes, &allowed_scopes) {
        return Err(oauth_error_response(Some(&q.redirect_uri), "invalid_scope", q.state.as_deref()));
    }

    let challenge = q.code_challenge.as_deref().unwrap_or("");
    let method = q.code_challenge_method.as_deref();
    if !challenge.is_empty() {
        if method != Some("S256") {
            return Err(oauth_error_response(Some(&q.redirect_uri), "invalid_request", q.state.as_deref()));
        }
    }
    if app.client_type.eq_ignore_ascii_case("public") {
        if challenge.is_empty() {
            return Err(oauth_error_response(Some(&q.redirect_uri), "invalid_request", q.state.as_deref()));
        }
        if method != Some("S256") {
            return Err(oauth_error_response(Some(&q.redirect_uri), "invalid_request", q.state.as_deref()));
        }
    }

    let scope_string = requested_scopes.join(" ");
    Ok(AuthorizeContext {
        client_id: app.id,
        redirect_uri: q.redirect_uri.clone(),
        scopes: requested_scopes,
        scope_string,
        state: q.state.clone(),
        code_challenge: q.code_challenge.clone(),
        code_challenge_method: q.code_challenge_method.clone(),
        app_name: app.name,
    })
}

async fn issue_auth_code(state: &AppState, user_id: &str, ctx: &AuthorizeContext) -> Result<String, Response> {
    let code = generate_token(32);
    let code_hash = hash_token(&code);
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::minutes(AUTH_CODE_TTL_MINUTES);
    let oauth_code = OAuthCode {
        code_hash,
        app_id: ctx.client_id.clone(),
        user_id: user_id.to_string(),
        redirect_uri: ctx.redirect_uri.clone(),
        scopes: ctx.scope_string.clone(),
        code_challenge: ctx.code_challenge.clone(),
        code_challenge_method: ctx.code_challenge_method.clone(),
        expires_at: format_rfc3339(expires_at),
        created_at: now.to_string(),
        consumed_at: None,
    };

    if let Err(e) = state.accounts.create_oauth_code(oauth_code).await {
        tracing::error!(error=?e, "failed to save auth code");
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    Ok(code)
}

async fn issue_tokens(
    state: &AppState,
    app_id: &str,
    user_id: &str,
    scopes: &str,
    rotate_refresh_id: Option<&str>,
) -> Result<(String, String, i64), Response> {
    let now = OffsetDateTime::now_utc();
    let access_token = generate_token(32);
    let refresh_token = generate_token(48);
    let access_hash = hash_token(&access_token);
    let refresh_hash = hash_token(&refresh_token);

    let access_expires = now + Duration::minutes(ACCESS_TOKEN_TTL_MINUTES);
    let refresh_expires = now + Duration::days(REFRESH_TOKEN_TTL_DAYS);

    let access_row = AppAccessToken {
        id: uuid::Uuid::new_v4().to_string(),
        token_hash: access_hash,
        app_id: app_id.to_string(),
        user_id: user_id.to_string(),
        scopes: scopes.to_string(),
        expires_at: format_rfc3339(access_expires),
        created_at: now.to_string(),
        last_used_at: None,
        revoked_at: None,
    };

    let refresh_id = uuid::Uuid::new_v4().to_string();
    let refresh_row = AppRefreshToken {
        id: refresh_id.clone(),
        token_hash: refresh_hash,
        app_id: app_id.to_string(),
        user_id: user_id.to_string(),
        scopes: scopes.to_string(),
        expires_at: format_rfc3339(refresh_expires),
        created_at: now.to_string(),
        revoked_at: None,
        rotation_parent_id: rotate_refresh_id.map(|s| s.to_string()),
        replaced_by_id: None,
    };

    if let Err(e) = state.accounts.create_app_access_token(access_row).await {
        tracing::error!(error=?e, "failed to save access token");
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    if let Err(e) = state.accounts.create_app_refresh_token(refresh_row).await {
        tracing::error!(error=?e, "failed to save refresh token");
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    if let Some(old_refresh_id) = rotate_refresh_id {
        let _ = state.accounts.revoke_app_refresh_token(old_refresh_id, Some(&refresh_id)).await;
    }

    Ok((access_token, refresh_token, ACCESS_TOKEN_TTL_MINUTES * 60))
}

async fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<(crate::models::application::Application, String), Response> {
    let (client_id, client_secret) = extract_client_credentials(headers, form_client_id, form_client_secret)
        .ok_or_else(|| token_error_response(StatusCode::UNAUTHORIZED, "invalid_client"))?;

    let app = match state.accounts.get_application(&client_id).await {
        Ok(Some(app)) => app,
        Ok(None) => return Err(token_error_response(StatusCode::UNAUTHORIZED, "invalid_client")),
        Err(e) => {
            tracing::error!(error=?e, "failed to load application");
            return Err(token_error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error"));
        }
    };

    if app.is_enabled != 1 {
        return Err(token_error_response(StatusCode::UNAUTHORIZED, "invalid_client"));
    }

    if app.client_type.eq_ignore_ascii_case("confidential") {
        let Some(secret) = client_secret else {
            return Err(token_error_response(StatusCode::UNAUTHORIZED, "invalid_client"));
        };
        let Some(expected) = app.client_secret_hash.as_deref() else {
            return Err(token_error_response(StatusCode::UNAUTHORIZED, "invalid_client"));
        };
        let provided_hash = hash_token(&secret);
        if provided_hash != expected {
            return Err(token_error_response(StatusCode::UNAUTHORIZED, "invalid_client"));
        }
    }

    Ok((app, client_id))
}

fn extract_client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Option<(String, Option<String>)> {
    if let Some(value) = headers.get(AUTHORIZATION) {
        if let Ok(header_str) = value.to_str() {
            if let Some(b64) = header_str.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                    if let Ok(pair) = String::from_utf8(decoded) {
                        let mut parts = pair.splitn(2, ':');
                        let id = parts.next().unwrap_or("").to_string();
                        let secret = parts.next().unwrap_or("").to_string();
                        if !id.is_empty() {
                            return Some((id, Some(secret)));
                        }
                    }
                }
            }
        }
    }

    form_client_id.map(|id| (id.to_string(), form_client_secret.map(|s| s.to_string())))
}

fn build_redirect_response(redirect_uri: &str, params: Vec<(String, String)>) -> Response {
    if let Ok(mut url) = Url::parse(redirect_uri) {
        {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in params {
                if !v.is_empty() {
                    pairs.append_pair(&k, &v);
                }
            }
        }
        return Redirect::temporary(url.as_str()).into_response();
    }
    (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_redirect_uri"}))).into_response()
}

fn oauth_error_response(redirect_uri: Option<&str>, error: &str, state: Option<&str>) -> Response {
    if let Some(uri) = redirect_uri {
        let mut params = vec![("error".to_string(), error.to_string())];
        if let Some(s) = state {
            params.push(("state".to_string(), s.to_string()));
        }
        return build_redirect_response(uri, params);
    }
    (StatusCode::BAD_REQUEST, Json(json!({"error": error}))).into_response()
}

fn token_error_response(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({"error": error}))).into_response()
}

fn normalize_scopes(scopes: Option<&str>) -> Vec<String> {
    let mut set = BTreeSet::new();
    if let Some(s) = scopes {
        for item in s.split_whitespace() {
            if !item.is_empty() {
                set.insert(item.to_string());
            }
        }
    }
    set.into_iter().collect()
}

fn scopes_within(requested: &[String], allowed: &[String]) -> bool {
    let req: HashSet<&str> = requested.iter().map(|s| s.as_str()).collect();
    let allow: HashSet<&str> = allowed.iter().map(|s| s.as_str()).collect();
    req.is_subset(&allow)
}

fn scopes_allow(allowed_scopes: &str, requested: &[String]) -> bool {
    let allowed = normalize_scopes(Some(allowed_scopes));
    scopes_within(requested, &allowed)
}

fn consent_scopes_allow(consent_scopes: &str, requested: &str) -> bool {
    let consent = normalize_scopes(Some(consent_scopes));
    let req = normalize_scopes(Some(requested));
    scopes_within(&req, &consent)
}

fn redirect_uri_allowed(redirects: &[crate::models::app_redirect_uri::AppRedirectUri], redirect_uri: &str) -> bool {
    redirects.iter().any(|r| r.redirect_uri == redirect_uri)
}

fn render_consent_page(ctx: &AuthorizeContext) -> String {
    let app_name = escape_html(&ctx.app_name);
    let client_id = escape_html(&ctx.client_id);
    let redirect_uri = escape_html(&ctx.redirect_uri);
    let scope_value = escape_html(&ctx.scope_string);
    let state_value = escape_html(&ctx.state.clone().unwrap_or_default());
    let code_challenge_value = escape_html(&ctx.code_challenge.clone().unwrap_or_default());
    let code_challenge_method_value = escape_html(&ctx.code_challenge_method.clone().unwrap_or_default());

    let scopes_html = if ctx.scopes.is_empty() {
        "<p>No additional scopes requested.</p>".to_string()
    } else {
        let items: String = ctx
            .scopes
            .iter()
            .map(|s| format!("<li>{}</li>", escape_html(s)))
            .collect();
        format!("<ul>{}</ul>", items)
    };

    format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize {app_name}</title>
  <link rel="stylesheet" href="/static/styles.css" />
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, sans-serif; margin: 0; }}
    main {{ max-width: 560px; margin: 10vh auto; padding: 24px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.06); }}
    h1 {{ margin-top: 0; font-size: 24px; }}
    .scopes {{ margin: 16px 0; }}
    button {{ padding: 10px 16px; border-radius: 8px; border: 1px solid #ddd; background: #fff; cursor: pointer; }}
    button.primary {{ background: #111; color: #fff; border-color: #111; }}
    .actions {{ display: flex; gap: 12px; margin-top: 16px; }}
  </style>
</head>
<body>
  <main>
    <h1>Authorize {app_name}</h1>
    <p>This application is requesting access to your oauth3 proxy.</p>
    <div class="scopes">
      {scopes_html}
    </div>
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="response_type" value="code" />
      <input type="hidden" name="client_id" value="{client_id}" />
      <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
      <input type="hidden" name="scope" value="{scope}" />
      <input type="hidden" name="state" value="{state}" />
      <input type="hidden" name="code_challenge" value="{code_challenge}" />
      <input type="hidden" name="code_challenge_method" value="{code_challenge_method}" />
      <div class="actions">
        <button class="primary" name="decision" value="approve" type="submit">Approve</button>
        <button name="decision" value="deny" type="submit">Deny</button>
      </div>
    </form>
  </main>
</body>
</html>"#,
        app_name = app_name,
        scopes_html = scopes_html,
        client_id = client_id,
        redirect_uri = redirect_uri,
        scope = scope_value,
        state = state_value,
        code_challenge = code_challenge_value,
        code_challenge_method = code_challenge_method_value,
    )
}

pub(crate) fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn generate_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn hash_token(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn is_expired(timestamp: &str) -> bool {
    if let Ok(expires) = OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339) {
        return OffsetDateTime::now_utc() > expires;
    }
    // Unparseable timestamps are treated as expired (fail closed)
    true
}

/// Format an OffsetDateTime as RFC 3339 for consistent timestamp storage.
fn format_rfc3339(dt: OffsetDateTime) -> String {
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| dt.to_string())
}

fn verify_pkce(challenge: &str, method: Option<&str>, verifier: &str) -> bool {
    if verifier.is_empty() {
        return false;
    }
    match method {
        Some("S256") | None => {
            let digest = sha2::Sha256::digest(verifier.as_bytes());
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
            encoded == challenge
        }
        _ => false,
    }
}

async fn consent_allows(state: &AppState, user_id: &str, app_id: &str, scopes: &str) -> bool {
    match state.accounts.get_user_consent(user_id, app_id).await {
        Ok(Some(consent)) => consent.revoked_at.is_none() && consent_scopes_allow(&consent.scopes, scopes),
        _ => false,
    }
}
