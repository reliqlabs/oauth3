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

    std::env::set_var("AUTH_DEX_MODE", "live");
    std::env::set_var("DEX_ISSUER", &dex_issuer);
    std::env::set_var("DEX_CLIENT_ID", "oauth3-dev");
    std::env::set_var("DEX_CLIENT_SECRET", "dex-secret");
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

    use oauth3::models::provider::Provider;
    let now = "2026-01-22T00:00:00Z".to_string();
    accounts.save_provider(Provider {
        id: "dex".into(),
        name: "Dex".into(),
        provider_type: "oidc".into(),
        mode: "live".into(),
        client_id: Some("oauth3-dev".into()),
        client_secret: Some("dex-secret".into()),
        issuer: Some(dex_issuer.clone()),
        auth_url: None,
        token_url: None,
        scopes: Some("openid profile email".into()),
        redirect_path: "/auth/callback/dex".into(),
        is_enabled: 1,
        created_at: now.clone(),
        updated_at: now.clone(),
        api_base_url: Some(dex_issuer.clone()),
    }).await.expect("save provider");

    let router = build_router(state.clone());
    (router, state)
}

#[tokio::test]
#[ignore]
#[serial]
async fn test_proxy_dex_userinfo() {
    let _guard = DockerComposeGuard::new();
    let dex_issuer = "http://localhost:5556/dex";
    wait_for_dex(dex_issuer).await;

    let (app, _state) = test_app_with_state(dex_issuer.to_string()).await;

    // Step 1: Start auth flow
    let auth_req = Request::builder()
        .uri("/auth/dex")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(auth_req).await.unwrap();

    assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = res.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(location.starts_with("http://localhost:5556/dex/auth"));

    let all_set_cookies: Vec<_> = res.headers().get_all(header::SET_COOKIE).iter().collect();
    let app_set_cookie = all_set_cookies.iter()
        .find(|c| c.to_str().unwrap().contains("oidc_tmp_dex"))
        .expect("oidc_tmp_dex cookie missing")
        .to_str()
        .unwrap();

    let state_param = location.split("state=").nth(1).unwrap().split('&').next().unwrap();

    // Step 2: Complete Dex flow with reqwest
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    let mut current_resp = client.get(location).send().await.expect("failed to redirect to dex");
    let mut code = String::new();

    loop {
        if current_resp.status() == StatusCode::FOUND || current_resp.status() == StatusCode::SEE_OTHER {
            let next_url = current_resp.headers().get(header::LOCATION).unwrap().to_str().unwrap().to_string();

            if next_url.starts_with("http://localhost:8080/auth/callback/dex") {
                code = next_url.split("code=").nth(1).unwrap().split('&').next().unwrap().to_string();
                break;
            }

            if next_url.contains("/auth/local") {
                let login_url = if next_url.starts_with("http") {
                    next_url.clone()
                } else {
                    format!("http://localhost:5556{}", next_url)
                };
                let form_resp = client.get(&login_url).send().await.expect("failed to get login form");
                let next_from_form = form_resp.headers().get(header::LOCATION).map(|v| v.to_str().unwrap().to_string());

                if let Some(next) = next_from_form {
                    let next_full = if next.starts_with("http") {
                        next
                    } else {
                        format!("http://localhost:5556{}", next)
                    };
                    current_resp = client.get(&next_full).send().await.expect("failed to follow from form");
                    continue;
                }

                let login_action = format!("http://localhost:5556/dex/auth/local/login?{}", next_url.split('?').nth(1).unwrap_or(""));
                current_resp = client.post(&login_action)
                    .form(&[("login", "admin@example.com"), ("password", "password")])
                    .send()
                    .await
                    .expect("failed to login");
                continue;
            }

            if next_url.contains("/approval") {
                current_resp = client.post(&format!("http://localhost:5556{}", next_url))
                    .form(&[("approval", "approve")])
                    .send()
                    .await
                    .expect("failed to approve");
                continue;
            }

            let next_full = if next_url.starts_with("http") {
                next_url
            } else {
                format!("http://localhost:5556{}", next_url)
            };
            current_resp = client.get(&next_full).send().await.expect("failed to follow redirect");
            continue;
        }

        // If we get 200 OK, we're likely at the login form
        if current_resp.status() == StatusCode::OK {
            let body = current_resp.text().await.expect("failed to read body");
            if body.contains("/dex/auth/local/login") || body.contains("name=\"login\"") {
                // Extract the action URL from the form (or reconstruct it)
                let login_action = if body.contains("action=\"") {
                    let action_start = body.find("action=\"").unwrap() + 8;
                    let action_end = body[action_start..].find('"').unwrap() + action_start;
                    let action = &body[action_start..action_end];
                    let action_decoded = action.replace("&amp;", "&");
                    if action_decoded.starts_with("http") {
                        action_decoded
                    } else {
                        format!("http://localhost:5556{}", action_decoded)
                    }
                } else {
                    // Fallback - construct from current URL
                    "http://localhost:5556/dex/auth/local/login".to_string()
                };

                current_resp = client.post(&login_action)
                    .form(&[("login", "admin@example.com"), ("password", "password")])
                    .send()
                    .await
                    .expect("failed to submit login");
                continue;
            }
        }

        break;
    }

    if code.is_empty() {
        panic!("Failed to get code from Dex");
    }

    // Step 3: Callback to our app with the real code
    let callback_req = Request::builder()
        .uri(format!("/auth/callback/dex?code={}&state={}", code, state_param))
        .header(header::COOKIE, app_set_cookie)
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(callback_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);

    let all_set_cookies: Vec<_> = res.headers().get_all(header::SET_COOKIE).iter().collect();
    let session_cookie = all_set_cookies.iter()
        .find(|c| c.to_str().unwrap().starts_with("sid="))
        .expect("session cookie missing")
        .to_str()
        .unwrap();

    // Step 4: Verify /me
    let me_req = Request::builder()
        .uri("/me")
        .header(header::COOKIE, session_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(me_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
    let user: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(user.get("user_id").is_some());

    // Step 5: Use proxy endpoint to call Dex UserInfo
    let proxy_req = Request::builder()
        .uri("/proxy/dex/userinfo")
        .header(header::COOKIE, session_cookie)
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(proxy_req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK, "Proxy request failed");

    let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
    let userinfo: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(userinfo.get("sub").is_some(), "Missing 'sub' claim");
    assert_eq!(
        userinfo.get("email").and_then(|v| v.as_str()),
        Some("admin@example.com"),
        "Email mismatch"
    );

}
