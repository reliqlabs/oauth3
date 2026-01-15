use axum::{body::Body, http::{Request, StatusCode, header}, Router};
use tower::Service;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use serde_json::json;
use rand::RngCore;
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};

/// Integration test for the full OIDC flow using a mocked Dex provider.
/// It covers:
/// 1. Redirecting to Dex (/auth/dex)
/// 2. Handling the callback from Dex (/auth/callback/dex)
/// 3. Exchanging the code for a token and verifying the ID token
/// 4. Establishing a session and accessing protected resources (/me)
async fn test_app(dex_issuer: String) -> Router {
    use oauth3::{app::{AppState, build_router}, db, repos, config as app_config};
    use oauth3::db::sqlite::make_pool;

    std::env::set_var("AUTH_DEX_MODE", "live");
    std::env::set_var("DEX_ISSUER", &dex_issuer);
    std::env::set_var("DEX_CLIENT_ID", "oauth3-dev");
    std::env::set_var("DEX_CLIENT_SECRET", "dex-secret");

    let db_path = "sqlite://:memory:".to_string();

    let cfg = oauth3::config::AppConfig {
        server: oauth3::config::ServerCfg {
            bind_addr: "127.0.0.1:0".to_string(),
            public_url: "http://localhost:8080".to_string(),
            cookie_key_base64: {
                let mut key = [0u8; 64];
                rand::rngs::OsRng.fill_bytes(&mut key);
                base64::engine::general_purpose::STANDARD.encode(key)
            },
        },
        db: oauth3::config::DbCfg { url: db_path.clone() },
    };

    let key_bytes = app_config::decode_cookie_key(&cfg.server.cookie_key_base64).expect("cookie key");
    let cookie_key = tower_cookies::Key::from(&key_bytes);

    let sqlite_pool = make_pool(&cfg.db.url).expect("sqlite pool");
    if let Ok(mut conn) = sqlite_pool.get() {
        let _ = db::migrations::run_sqlite_migrations(&mut *conn);
    }

    let accounts: std::sync::Arc<dyn repos::AccountsRepo> = oauth3::repos::sqlite::SqliteAccountsRepo::new(sqlite_pool.clone());

    let state = AppState {
        config: cfg.clone(),
        cookie_key,
        accounts,
        oidc: oauth3::auth::oidc::OidcSettings::from_config(&cfg).expect("oidc settings"),
        #[cfg(feature = "sqlite")] 
        sqlite: sqlite_pool,
        #[cfg(feature = "pg")]
        pg: oauth3::db::pg::make_pool("").await.unwrap(), 
    };

    build_router(state)
}

#[tokio::test]
async fn full_dex_oidc_flow() {
    let mock_server = MockServer::start().await;

    // RSA Key for signing
    let rsa_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("failed to generate key");
    let pem = pkcs8::EncodePrivateKey::to_pkcs8_pem(&rsa_key, pkcs8::LineEnding::LF).unwrap();
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    
    // Discovery
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": mock_server.uri(),
            "authorization_endpoint": format!("{}/auth", mock_server.uri()),
            "token_endpoint": format!("{}/token", mock_server.uri()),
            "jwks_uri": format!("{}/keys", mock_server.uri()),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })))
        .mount(&mock_server)
        .await;

    // JWKS
    use rsa::traits::PublicKeyParts;
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa_key.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa_key.e().to_bytes_be());

    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "test-key",
                "n": n,
                "e": e
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut app = test_app(mock_server.uri()).await;

    // Step 1: Hit /auth/dex
    let req = Request::builder()
        .uri("/auth/dex")
        .body(Body::empty())
        .unwrap();
    let res = app.call(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = res.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    let set_cookie = res.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
    
    let url = url::Url::parse(location).unwrap();
    let state_param = url.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()).unwrap();
    let nonce_param = url.query_pairs().find(|(k, _)| k == "nonce").map(|(_, v)| v.into_owned()).unwrap();

    // ID Token
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = json!({
        "iss": mock_server.uri(),
        "sub": "admin-id",
        "aud": "oauth3-dev",
        "exp": now + 3600,
        "iat": now,
        "nonce": nonce_param,
        "email": "admin@example.com",
        "name": "Admin User"
    });
    let mut jwt_header = Header::new(jsonwebtoken::Algorithm::RS256);
    jwt_header.kid = Some("test-key".to_string());
    let id_token = encode(&jwt_header, &claims, &encoding_key).unwrap();

    // Mock Token Response
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "dummy-access-token",
            "token_type": "Bearer",
            "id_token": id_token,
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;

    // Step 2: Callback
    let callback_req = Request::builder()
        .uri(format!("/auth/callback/dex?code=dummy-code&state={}", state_param))
        .header(header::COOKIE, set_cookie)
        .body(Body::empty())
        .unwrap();
    
    let res = app.call(callback_req).await.unwrap();
    
    // Expect redirect to home after successful login
    assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/");
    
    let all_set_cookies: Vec<_> = res.headers().get_all(header::SET_COOKIE).iter().collect();
    let session_cookie = all_set_cookies.iter().find(|c| c.to_str().unwrap().starts_with("sid=")).expect("session cookie missing");
    let session_cookie_str = session_cookie.to_str().unwrap();

    // Step 3: Verify /me
    let me_req = Request::builder()
        .uri("/me")
        .header(header::COOKIE, session_cookie_str)
        .body(Body::empty())
        .unwrap();
    let res = app.call(me_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    
    let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
    let user: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(user.get("user_id").is_some());
}
