use axum::http::{Request, StatusCode, header::LOCATION};
use axum::body::Body;
use tower::ServiceExt; // for oneshot

use diesel::prelude::*;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn oauth_login_redirects_to_provider() {
    let test_db = common::init_test_db().expect("init db");

    // Insert a mock provider pointing at example.com
    {
        use oauth3::schema::oauth_providers::dsl as p;
        let mut conn = test_db.pool.get().unwrap();
        diesel::insert_into(oauth3::schema::oauth_providers::table)
            .values((
                p::key.eq("mock"),
                p::auth_url.eq("https://example.com/authorize"),
                p::token_url.eq("https://example.com/token"),
                p::userinfo_url.eq("https://example.com/userinfo"),
                p::client_id.eq("CLIENT"),
                p::client_secret.eq("SECRET"),
                p::redirect_url.eq("http://localhost:8080/auth/callback"),
                p::scopes.eq("openid,profile,email"),
            ))
            .execute(&mut conn)
            .unwrap();
    }

    let cfg = oauth3::config::AppConfig {
        server_addr: "127.0.0.1:0".into(),
        database_url: test_db.path.clone(),
        jwt_secret: "test-secret".into(),
    };

    let app = common::build_test_app(cfg, test_db.pool.clone());

    let res = app
        .oneshot(Request::get("/auth/login/mock").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::SEE_OTHER); // 303
    let loc = res.headers().get(LOCATION).expect("Location header").to_str().unwrap();
    assert!(loc.starts_with("https://example.com/authorize"), "Location was: {}", loc);
    assert!(loc.contains("client_id=CLIENT"), "Location was: {}", loc);
    assert!(loc.contains("redirect_uri="), "Location was: {}", loc);
    assert!(loc.contains("scope="), "Location was: {}", loc);
    assert!(loc.contains("state="), "Location was: {}", loc);
}