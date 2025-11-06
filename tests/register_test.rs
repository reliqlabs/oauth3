use axum::http::{Request, header::CONTENT_TYPE, StatusCode};
use axum::body::{Body, to_bytes};
use serde_json::json;
use tower::ServiceExt; // for oneshot

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn register_creates_user() {
    let test_db = common::init_test_db().expect("init db");

    let cfg = oauth3::config::AppConfig {
        server_addr: "127.0.0.1:0".into(),
        database_url: test_db.path.clone(),
        jwt_secret: "test-secret".into(),
    };

    let app = common::build_test_app(cfg, test_db.pool.clone());

    let body = json!({
        "email": "you@example.com",
        "name": "You",
        "password": "Secret123!"
    });

    let res = app
        .oneshot(
            Request::post("/api/register")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["email"], "you@example.com");
    assert!(v["id"].is_number());
}
