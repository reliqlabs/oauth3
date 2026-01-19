use axum::{body::Body, http::{Request, StatusCode, header}, Router};
use tower::ServiceExt;
use std::process::Command;
use std::time::Duration;
use std::sync::Arc;
use serial_test::serial;
use oauth3::app::AppState;

struct DockerComposeGuard;

impl DockerComposeGuard {
    fn new() -> Self {
        println!("Stopping any existing containers...");
        let _ = Command::new("docker-compose")
            .args(&["down", "-v"])
            .status();

        println!("Starting dex and db services...");
        let status = Command::new("docker-compose")
            .args(&["up", "-d", "dex", "db"])
            .status()
            .expect("failed to run docker-compose");

        if !status.success() {
            panic!("docker-compose up failed");
        }
        
        Self
    }
}

impl Drop for DockerComposeGuard {
    fn drop(&mut self) {
        println!("Tearing down containers...");
        let _ = Command::new("docker-compose")
            .args(&["down", "-v"])
            .status();
    }
}

async fn wait_for_dex(issuer: &str) {
    let client = reqwest::Client::new();
    let discovery_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    
    for _ in 0..30 {
        if let Ok(resp) = client.get(&discovery_url).send().await {
            if resp.status().is_success() {
                println!("Dex is ready!");
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("Dex failed to become ready at {}", discovery_url);
}

async fn test_app_with_state(dex_issuer: String) -> (Router, AppState) {
    use oauth3::{app::{AppState, build_router}, repos, config as app_config};
    
    // Configure app to use the real Dex we just started
    std::env::set_var("AUTH_DEX_MODE", "live");
    std::env::set_var("DEX_ISSUER", &dex_issuer);
    std::env::set_var("DEX_CLIENT_ID", "oauth3-dev");
    std::env::set_var("DEX_CLIENT_SECRET", "dex-secret");
    // Use the sqlite DB for simplicity in tests if pg is not available
    std::env::set_var("DATABASE_URL", "sqlite://test.db");
    std::env::set_var("APP_PUBLIC_URL", "http://localhost:8080");

    let cfg = oauth3::config::AppConfig::load().expect("failed to load config");
    let key_bytes = app_config::decode_cookie_key(&cfg.server.cookie_key_base64).expect("cookie key");
    let cookie_key = tower_cookies::Key::from(&key_bytes);

    let sqlite_pool = oauth3::db::sqlite::make_pool("sqlite::memory:").expect("sqlite pool");
    {
        let mut conn = sqlite_pool.get().expect("failed to get sqlite conn");
        let _ = oauth3::db::migrations::run_sqlite_migrations(&mut *conn);
    }

    let accounts: Arc<dyn repos::AccountsRepo> = oauth3::repos::sqlite::SqliteAccountsRepo::new(sqlite_pool.clone());

    let oidc = oauth3::auth::oidc::OidcSettings::from_config(&cfg).expect("oidc settings");
    let state = AppState {
        config: cfg.clone(),
        cookie_key,
        accounts: accounts.clone(),
        oidc,
        #[cfg(feature = "sqlite")] 
        sqlite: sqlite_pool,
        #[cfg(feature = "pg")]
        pg: oauth3::db::pg::make_pool("").await.unwrap(), 
    };

    // Explicitly seed the dex provider for the test
    use oauth3::models::provider::Provider;
    let now = "2026-01-15T00:00:00Z".to_string();
    accounts.save_provider(Provider {
        id: "dex".into(),
        name: "Dex".into(),
        provider_type: "oidc".into(),
        mode: "live".into(),
        client_id: Some("oauth3-dev".into()),
        client_secret: Some("dex-secret".into()),
        issuer: Some(dex_issuer),
        auth_url: None,
        token_url: None,
        redirect_path: "/auth/callback/dex".into(),
        is_enabled: 1,
        created_at: now.clone(),
        updated_at: now.clone(),
    }).await.expect("failed to seed dex provider");

    (build_router(state.clone()), state)
}

#[tokio::test]
#[ignore] // Requires working Docker daemon
#[serial]
async fn full_dex_oidc_flow_with_docker() {
    let _guard = DockerComposeGuard::new();
    let dex_issuer = "http://localhost:5556/dex";
    wait_for_dex(dex_issuer).await;

    let (app, state) = test_app_with_state(dex_issuer.to_string()).await;
    let accounts = state.accounts.clone();

    // Step 1: Start auth flow in our app to get state/nonce cookies
    let req = Request::builder()
        .uri("/auth/dex")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = res.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    
    // The generalized OIDC implementation uses a provider-specific cookie
    let app_set_cookie = res.headers().get_all(header::SET_COOKIE)
        .iter()
        .find(|c| c.to_str().unwrap().contains("oidc_tmp_dex"))
        .expect("oidc_tmp_dex cookie missing")
        .to_str().unwrap().to_string();
    
    let url = url::Url::parse(location).unwrap();
    let state_param = url.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()).unwrap();
    let nonce_param = url.query_pairs().find(|(k, _)| k == "nonce").map(|(_, v)| v.into_owned()).unwrap();

    println!("App initiated flow. State: {}, Nonce: {}", state_param, nonce_param);

    // Step 2: Instead of scraping Dex HTML, we'll hit its TOKEN endpoint directly
    // but to do that we need an authorization code. 
    // Since obtaining a code usually requires browser interaction, 
    // and the user wants to "ignore the html", 
    // we can demonstrate that the app's callback handler works by providing it a valid ID token
    // that it would expect from Dex.
    
    // However, the app's `callback_dex_live` will try to exchange a code for a token with the REAL Dex.
    // So we DO need a real code from Dex.
    
    // BUT if we want to "hit the oauth api directly", we can use the Resource Owner Password Credentials Grant
    // if Dex supports it, or just use Dex's static passwords.
    
    // Actually, the most "direct" way to test our API without HTML scraping is to 
    // MOCK the token exchange if we want to skip Dex's frontend, 
    // OR we can use the fact that Dex is running and we can just use its Token API if we had a code.
    
    // Given the constraint "ignore the html, and hit the oauth api directly", 
    // I will use the PASSWORD grant type if Dex supports it to get a token, 
    // OR I will simply use a more robust way to get the code.
    
    // Dex DOES support the password grant if configured, but we didn't enable it in dex-config.yaml for clients.
    
    // Let's try to get a code from Dex via a direct POST to its local auth endpoint, 
    // bypassing the GET and scraping.
    
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // The authorization URL we got from Step 1:
    // http://localhost:5556/dex/auth?response_type=code&client_id=oauth3-dev&state=...&nonce=...&...
    
    // Hit the authorization endpoint. It will set some cookies and redirect to /dex/auth/local...
    let mut dex_resp = client.get(location).send().await.expect("failed to call dex");
    while dex_resp.status().is_redirection() {
        let new_loc = dex_resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        let new_url = if new_loc.starts_with("http") { new_loc.to_string() } else { format!("http://localhost:5556{}", new_loc) };
        dex_resp = client.get(&new_url).send().await.expect("failed to follow dex redirect");
    }

    // Now we are likely at the login page. Instead of scraping, we KNOW the structure of the login POST URL.
    // It's usually /dex/auth/local/login?back=&state=<state_from_dex>
    // The <state_from_dex> is in the URL of the current page.
    let dex_auth_state = dex_resp.url().query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()).expect("state param missing in dex url");
    
    let login_url = format!("http://localhost:5556/dex/auth/local/login?state={}", dex_auth_state);
    
    println!("Posting credentials directly to {}", login_url);
    let login_resp = client.post(&login_url)
        .form(&[
            ("login", "admin@example.com"),
            ("password", "password"),
        ])
        .send()
        .await
        .expect("failed to post login to dex");

    // This should redirect to /dex/approval... or directly back to the app if skipApproval is true.
    let mut current_resp = login_resp;
    let mut code = String::new();

    loop {
        if current_resp.status().is_redirection() {
            let loc = current_resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
            if loc.contains("code=") {
                let full_loc = if loc.starts_with("http") { loc.to_string() } else { format!("http://localhost:8080{}", loc) };
                let u = url::Url::parse(&full_loc).unwrap();
                code = u.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.into_owned()).unwrap();
                break;
            }
            
            let next_url = if loc.starts_with("http") { loc.to_string() } else { format!("http://localhost:5556{}", loc) };
            
            // If it's an approval page, we might need to POST to it.
            if next_url.contains("/dex/approval") {
                println!("Hit approval page, approving directly...");
                let approval_req = next_url.split("req=").last().unwrap().split('&').next().unwrap();
                // Extract HMAC if present
                let hmac = if next_url.contains("hmac=") {
                    Some(next_url.split("hmac=").last().unwrap().split('&').next().unwrap())
                } else {
                    None
                };

                let mut params = vec![
                    ("req", approval_req),
                    ("approval", "approve"),
                ];
                if let Some(h) = hmac {
                    params.push(("hmac", h));
                }

                let approval_url = "http://localhost:5556/dex/approval";
                current_resp = client.post(approval_url)
                    .form(&params)
                    .send()
                    .await
                    .expect("failed to approve");
                continue;
            }

            current_resp = client.get(&next_url).send().await.expect("failed to follow redirect");
            continue;
        }
        break;
    }

    if code.is_empty() {
        panic!("Failed to get code from Dex without scraping. Status: {}, Body: {}", current_resp.status(), current_resp.text().await.unwrap());
    }

    println!("Successfully obtained code: {}", code);

    // Step 3: Callback to our app with the real code
    let callback_req = Request::builder()
        .uri(format!("/auth/callback/dex?code={}&state={}", code, state_param))
        .header(header::COOKIE, app_set_cookie)
        .body(Body::empty())
        .unwrap();
    
    let res = app.clone().oneshot(callback_req).await.unwrap();
    
    if res.status() != StatusCode::TEMPORARY_REDIRECT {
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        panic!("Callback failed with status {}. Body: {}", StatusCode::TEMPORARY_REDIRECT, String::from_utf8_lossy(&body));
    }
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/");
    
    let all_set_cookies: Vec<_> = res.headers().get_all(header::SET_COOKIE).iter().collect();
    let session_cookie = all_set_cookies.iter().find(|c| c.to_str().unwrap().starts_with("sid=")).expect("session cookie missing");
    let session_cookie_str = session_cookie.to_str().unwrap();

    // Step 4: Verify /me
    let me_req = Request::builder()
        .uri("/me")
        .header(header::COOKIE, session_cookie_str)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(me_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    
    let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
    let user: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(user.get("user_id").is_some());
    println!("Flow complete! User: {}", user);

    // Step 5: Verify Token Storage and Rotation
    let user_id = user["user_id"].as_str().unwrap();
    let identities = accounts.list_identities(user_id).await.unwrap();
    let dex_identity = identities.iter().find(|i| i.provider_key == "dex").expect("dex identity not found");
    
    assert!(dex_identity.access_token.is_some());
    assert!(dex_identity.refresh_token.is_some()); // Dex usually provides refresh tokens
    let old_access_token = dex_identity.access_token.clone().unwrap();
    println!("Initial access token: {}", old_access_token);

    // Try to refresh
    oauth3::auth::oidc::refresh_token(&state, "dex", &dex_identity.subject).await.expect("refresh token failed");

    let identities_after = accounts.list_identities(user_id).await.unwrap();
    let dex_identity_after = identities_after.iter().find(|i| i.provider_key == "dex").unwrap();
    let new_access_token = dex_identity_after.access_token.clone().unwrap();
    println!("New access token: {}", new_access_token);

    assert_ne!(old_access_token, new_access_token);
}

#[tokio::test]
#[ignore]
#[serial]
async fn test_dex_discovery() {
    let _guard = DockerComposeGuard::new();
    let dex_issuer = "http://localhost:5556/dex";
    wait_for_dex(dex_issuer).await;

    let client = reqwest::Client::new();
    let discovery_url = format!("{}/.well-known/openid-configuration", dex_issuer);
    let resp = client.get(&discovery_url).send().await.expect("failed to get discovery");
    assert_eq!(resp.status(), StatusCode::OK);
    let config: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(config["issuer"], dex_issuer);
}
