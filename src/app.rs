use axum::{middleware, routing::{get, post}, Router};
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
    use std::collections::HashMap;
    let now = time::OffsetDateTime::now_utc().to_string();

    // Collect all PROVIDER_* env vars and group by provider ID
    let mut providers: HashMap<String, HashMap<String, String>> = HashMap::new();

    for (key, value) in std::env::vars() {
        if let Some(rest) = key.strip_prefix("PROVIDER_") {
            // Format: PROVIDER_<ID>_<FIELD>
            if let Some((provider_id, field)) = rest.split_once('_') {
                let provider_id = provider_id.to_lowercase();
                providers.entry(provider_id)
                    .or_insert_with(HashMap::new)
                    .insert(field.to_lowercase(), value);
            }
        }
    }

    tracing::info!("Found {} provider(s) in environment", providers.len());

    // Process each discovered provider
    for (provider_id, fields) in providers {
        // Skip if already exists in DB
        if state.accounts.get_provider(&provider_id).await?.is_some() {
            tracing::debug!("Provider '{}' already exists, skipping", provider_id);
            continue;
        }

        // Required fields
        let Some(provider_type) = fields.get("type") else {
            tracing::warn!("Provider '{}' missing TYPE field, skipping", provider_id);
            continue;
        };

        // Build provider from env vars
        let name = fields.get("name")
            .map(|s| s.to_string())
            .unwrap_or_else(|| provider_id.to_uppercase());

        let mode = fields.get("mode")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "placeholder".to_string());

        let provider = Provider {
            id: provider_id.clone(),
            name,
            provider_type: provider_type.clone(),
            mode,
            client_id: fields.get("client_id").cloned(),
            client_secret: fields.get("client_secret").cloned(),
            issuer: fields.get("issuer").cloned(),
            auth_url: fields.get("auth_url").cloned(),
            token_url: fields.get("token_url").cloned(),
            scopes: fields.get("scopes").cloned(),
            redirect_path: fields.get("redirect_path")
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("/auth/callback/{}", provider_id)),
            is_enabled: fields.get("enabled")
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(1),
            created_at: now.clone(),
            updated_at: now.clone(),
            api_base_url: fields.get("api_base_url").cloned(),
        };

        tracing::info!("Seeding provider '{}' ({})", provider.id, provider.name);
        state.accounts.save_provider(provider).await?;
    }

    Ok(())
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(crate::web::pages::index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/attestation", get(crate::web::handlers::attestation::attestation))
        .route("/info", get(crate::web::handlers::attestation::info))
        .route("/verify", post(crate::web::handlers::attestation::verify))
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
        // API key management
        .route("/account/api-keys", get(crate::web::handlers::account::list_api_keys))
        .route("/account/api-keys", post(crate::web::handlers::account::create_api_key))
        .route("/account/api-keys/{key_id}", axum::routing::delete(crate::web::handlers::account::delete_api_key))
        // OAuth proxy endpoint - forwards authenticated requests to provider APIs
        .route("/proxy/{provider}/{*path}",
            axum::routing::any(crate::web::proxy::proxy_request))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state)
        .layer(middleware::from_fn(crate::web::middleware::attestation_middleware))
        .layer(CookieManagerLayer::new())
        .layer(TraceLayer::new_for_http())
}
