use axum::http::Request;
use axum::http::StatusCode;
use axum::body::{Body, to_bytes};
use tower::ServiceExt; // for oneshot

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn health_ok() {
    let test_db = common::init_test_db().expect("init db");

    let cfg = oauth3::config::AppConfig {
        server_addr: "127.0.0.1:0".into(),
        database_url: test_db.path.clone(),
        jwt_secret: "test-secret".into(),
    };

    let app = common::build_test_app(cfg, test_db.pool.clone());

    let res = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(body.as_ref(), br#"{"status":"ok"}"#);
}
