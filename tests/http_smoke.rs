use axum::{body::Body, http::{Request, StatusCode}};
use tower::ServiceExt; // for `oneshot`
use rand::RngCore;

// Build a test app router backed by a temporary SQLite database.
async fn test_app() -> axum::Router {
    use oauth3::{app::{AppState, build_router}, db, repos, config as app_config};
    use oauth3::db::sqlite::make_pool;

    // Force placeholder mode for deterministic tests (no outbound calls)
    std::env::set_var("AUTH_GOOGLE_MODE", "placeholder");

    // Use in-memory sqlite for tests
    let db_path = "sqlite://:memory:".to_string();

    // Build a minimal config
    let cfg = oauth3::config::AppConfig {
        server: oauth3::config::ServerCfg {
            bind_addr: "127.0.0.1:0".to_string(),
            public_url: "http://127.0.0.1:8080".to_string(),
            cookie_key_base64: {
                // 64 random bytes base64
                let mut key = [0u8; 64];
                rand::rngs::OsRng.fill_bytes(&mut key);
                base64::engine::general_purpose::STANDARD.encode(key)
            },
        },
        db: oauth3::config::DbCfg { url: db_path.clone() },
    };

    // Cookie key
    let key_bytes = app_config::decode_cookie_key(&cfg.server.cookie_key_base64).expect("cookie key");
    let cookie_key = tower_cookies::Key::from(&key_bytes);

    // SQLite pool and migrations
    let sqlite_pool = make_pool(&cfg.db.url).expect("sqlite pool");
    if let Ok(mut conn) = sqlite_pool.get() {
        let _ = db::migrations::run_sqlite_migrations(&mut *conn);
    }

    // Accounts repo (sqlite adapter)
    let accounts: std::sync::Arc<dyn repos::AccountsRepo> = oauth3::repos::sqlite::SqliteAccountsRepo::new(sqlite_pool.clone());

    let state = AppState {
        config: cfg.clone(),
        cookie_key,
        accounts,
        oidc: oauth3::auth::oidc::OidcSettings::from_config(&cfg).expect("oidc settings"),
        #[cfg(feature = "sqlite")] 
        sqlite: sqlite_pool,
        #[cfg(feature = "pg")]
        pg: oauth3::db::pg::make_pool("").await.unwrap(), // unused under sqlite feature
    };

    build_router(state)
}

#[tokio::test]
async fn healthz_ok() {
    let app = test_app().await;
    let res = app
        .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_page_loads() {
    let app = test_app().await;
    let res = app
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn placeholder_auth_sets_session_and_me_works() {
    let mut app = test_app().await;

    // Call the placeholder callback which issues a session cookie
    let resp = app
        .ready()
        .await
        .unwrap()
        .call(Request::builder().uri("/auth/callback/google").body(Body::empty()).unwrap())
        .await
        .unwrap();

    // Extract Set-Cookie
    let set_cookie = resp.headers().get(axum::http::header::SET_COOKIE).cloned();
    assert!(set_cookie.is_some(), "expected set-cookie header");

    // Use cookie to call /me
    let req = Request::builder()
        .uri("/me")
        .header(axum::http::header::COOKIE, set_cookie.unwrap())
        .body(Body::empty())
        .unwrap();
    let res = app.ready().await.unwrap().call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
