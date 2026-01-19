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

    tracing::info!("🚀 Starting oauth3 server...");

    // Load configuration
    tracing::info!("📋 Loading configuration from environment...");
    let config = AppConfig::load()?;
    tracing::info!(
        bind_addr = %config.server.bind_addr,
        public_url = %config.server.public_url,
        db_url = %config.db.url,
        "✓ Configuration loaded"
    );

    // Prepare cookie key
    let key_bytes = decode_cookie_key(&config.server.cookie_key_base64)?;
    let cookie_key = Key::from(&key_bytes);
    tracing::info!("🔐 Cookie key loaded and validated");

    // Initialize DB pool and run migrations when applicable
    #[cfg(feature = "sqlite")]
    let sqlite_pool = {
        tracing::info!("🗄️  Connecting to SQLite database...");
        let pool = crate::db::sqlite::make_pool(&config.db.url)?;
        // Run migrations eagerly on startup
        if let Ok(mut conn) = pool.get() {
            tracing::info!("🔄 Running SQLite migrations...");
            let _ = crate::db::migrations::run_sqlite_migrations(&mut conn);
            tracing::info!("✓ SQLite migrations complete");
        }
        pool
    };

    #[cfg(feature = "pg")]
    let pg_pool = {
        tracing::info!("🗄️  Connecting to Postgres database...");
        let pool = crate::db::pg::make_pool(&config.db.url).await?;
        tracing::info!("✓ Database connection pool established");
        tracing::info!("🔄 Running Postgres migrations...");
        crate::db::migrations::run_pg_migrations_sync(&config.db.url)?;
        tracing::info!("✓ Postgres migrations complete");
        pool
    };

    // Build repository (feature-specific) behind a trait object
    #[cfg(feature = "sqlite")]
    let accounts: Arc<dyn crate::repos::AccountsRepo> = crate::repos::sqlite::SqliteAccountsRepo::new(sqlite_pool.clone());
    #[cfg(feature = "pg")]
    let accounts: Arc<dyn crate::repos::AccountsRepo> = crate::repos::pg::PgAccountsRepo::new(pg_pool.clone());

    tracing::info!("🔧 Initializing OIDC settings...");
    let oidc = crate::auth::oidc::OidcSettings::from_config(&config)?;

    let state = AppState {
        config: config.clone(),
        cookie_key: cookie_key.clone(),
        accounts: accounts.clone(),
        oidc,
        #[cfg(feature = "sqlite")]
        sqlite: sqlite_pool,
        #[cfg(feature = "pg")]
        pg: pg_pool,
    };

    // Seed providers from environment for backward compatibility/initial setup
    if let Err(e) = seed_providers_from_env(&state).await {
        tracing::error!(error=?e, "failed to seed providers from environment");
    }

    tracing::info!("🛣️  Building router with {} routes", 9);
    let app = build_router(state);

    let addr = config.server.bind_addr.clone();
    tracing::info!("🌐 Server listening on {}", addr);
    tracing::info!("✨ Ready to accept connections!");

    // Axum 0.8 uses hyper directly for serving
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn seed_providers_from_env(state: &AppState) -> anyhow::Result<()> {
    use crate::models::provider::Provider;
    let now = time::OffsetDateTime::now_utc().to_string();

    // Helper to get env with default
    let get_env = |k: &str, default: &str| std::env::var(k).unwrap_or_else(|_| default.to_string());

    // 1. Google
    if state.accounts.get_provider("google").await?.is_none() {
        let mode = get_env("AUTH_GOOGLE_MODE", "placeholder");
        state.accounts.save_provider(Provider {
            id: "google".into(),
            name: "Google".into(),
            provider_type: "oidc".into(),
            mode,
            client_id: std::env::var("GOOGLE_CLIENT_ID").ok(),
            client_secret: std::env::var("GOOGLE_CLIENT_SECRET").ok(),
            issuer: Some(get_env("GOOGLE_ISSUER", "https://accounts.google.com")),
            auth_url: None,
            token_url: None,
            scopes: std::env::var("GOOGLE_SCOPES").ok(),
            redirect_path: "/auth/callback/google".into(),
            is_enabled: 1,
            created_at: now.clone(),
            updated_at: now.clone(),
        }).await?;
    }

    // 2. GitHub
    if state.accounts.get_provider("github").await?.is_none() {
        let mode = get_env("AUTH_GITHUB_MODE", "placeholder");
        state.accounts.save_provider(Provider {
            id: "github".into(),
            name: "GitHub".into(),
            provider_type: "oauth2".into(),
            mode,
            client_id: std::env::var("GITHUB_CLIENT_ID").ok(),
            client_secret: std::env::var("GITHUB_CLIENT_SECRET").ok(),
            issuer: None,
            auth_url: Some("https://github.com/login/oauth/authorize".into()),
            token_url: Some("https://github.com/login/oauth/access_token".into()),
            scopes: std::env::var("GITHUB_SCOPES").ok(),
            redirect_path: "/auth/callback/github".into(),
            is_enabled: 1,
            created_at: now.clone(),
            updated_at: now.clone(),
        }).await?;
    }

    // 3. Dex
    if state.accounts.get_provider("dex").await?.is_none() {
        let mode = get_env("AUTH_DEX_MODE", "placeholder");
        state.accounts.save_provider(Provider {
            id: "dex".into(),
            name: "Dex".into(),
            provider_type: "oidc".into(),
            mode,
            client_id: std::env::var("DEX_CLIENT_ID").ok(),
            client_secret: std::env::var("DEX_CLIENT_SECRET").ok(),
            issuer: Some(get_env("DEX_ISSUER", "http://localhost:5556/dex")),
            auth_url: None,
            token_url: None,
            scopes: std::env::var("DEX_SCOPES").ok(),
            redirect_path: "/auth/callback/dex".into(),
            is_enabled: 1,
            created_at: now.clone(),
            updated_at: now.clone(),
        }).await?;
    }

    Ok(())
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(crate::web::pages::index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/login", get(crate::web::pages::login))
        .route("/account", get(crate::web::pages::account))
        .route("/auth/{provider}", get(crate::web::handlers::auth::start))
        .route("/auth/callback/{provider}", get(crate::web::handlers::auth::callback))
        .route("/me", get(crate::web::handlers::account::me))
        .route("/providers", get(crate::web::handlers::account::list_providers))
        .route("/logout", post(crate::web::handlers::account::logout))
        .route("/account/linked-identities", get(crate::web::handlers::account::list_identities))
        .route("/account/link/{provider}", post(crate::web::handlers::account::start_link_provider))
        .route("/account/unlink/{provider}", post(crate::web::handlers::account::unlink_provider))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state)
        .layer(CookieManagerLayer::new())
        .layer(TraceLayer::new_for_http())
}
