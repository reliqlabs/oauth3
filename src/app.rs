use axum::{routing::{get, post}, Router};
use tower_cookies::{CookieManagerLayer, Key};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::EnvFilter;
use crate::config::{AppConfig, decode_cookie_key};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub cookie_key: Key,
    pub accounts: Arc<dyn crate::repos::AccountsRepo>,
    pub oidc: crate::auth::oidc::OidcSettings,
    #[cfg(feature = "sqlite")]
    pub sqlite: crate::db::sqlite::SqlitePool,
    #[cfg(feature = "pg")]
    pub pg: crate::db::pg::PgPool,
}

pub async fn run() -> anyhow::Result<()> {
    // logging
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // Load configuration
    let config = AppConfig::load()?;
    // Prepare cookie key
    let key_bytes = decode_cookie_key(&config.server.cookie_key_base64)?;
    let cookie_key = Key::from(&key_bytes);

    // Initialize DB pool and run migrations when applicable
    #[cfg(feature = "sqlite")]
    let sqlite_pool = {
        let pool = crate::db::sqlite::make_pool(&config.db.url)?;
        // Run migrations eagerly on startup
        if let Ok(mut conn) = pool.get() {
            let _ = crate::db::migrations::run_sqlite_migrations(&mut conn);
        }
        pool
    };

    #[cfg(feature = "pg")]
    let pg_pool = {
        let pool = crate::db::pg::make_pool(&config.db.url).await?;
        // Migrations for pg can be handled externally for now (diesel migration run)
        pool
    };

    // Build repository (feature-specific) behind a trait object
    #[cfg(feature = "sqlite")]
    let accounts: Arc<dyn crate::repos::AccountsRepo> = crate::repos::sqlite::SqliteAccountsRepo::new(sqlite_pool.clone());
    #[cfg(feature = "pg")]
    let accounts: Arc<dyn crate::repos::AccountsRepo> = crate::repos::pg::PgAccountsRepo::new(pg_pool.clone());

    let state = AppState {
        config: config.clone(),
        cookie_key: cookie_key.clone(),
        accounts,
        oidc: crate::auth::oidc::OidcSettings::from_config(&config)?,
        #[cfg(feature = "sqlite")]
        sqlite: sqlite_pool,
        #[cfg(feature = "pg")]
        pg: pg_pool,
    };

    let app = build_router(state);

    let addr = config.server.bind_addr.clone();
    tracing::info!(%addr, "listening");
    // Axum 0.8 uses hyper directly for serving
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/login", get(crate::web::pages::login))
        .route("/account", get(crate::web::pages::account))
        .route("/auth/{provider}", get(crate::web::handlers::auth::start))
        .route("/auth/callback/{provider}", get(crate::web::handlers::auth::callback))
        .route("/me", get(crate::web::handlers::account::me))
        .route("/logout", post(crate::web::handlers::account::logout))
        .route("/account/linked-identities", get(crate::web::handlers::account::list_identities))
        .route("/account/link/{provider}", post(crate::web::handlers::account::start_link_provider))
        .route("/account/unlink/{provider}", post(crate::web::handlers::account::unlink_provider))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state)
        .layer(CookieManagerLayer::new())
        .layer(TraceLayer::new_for_http())
}
