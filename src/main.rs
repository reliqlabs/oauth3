use axum::{Router, routing::{get, post}};
use tower_http::{cors::{Any, CorsLayer}, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use oauth3::{config::AppConfig, db::{self, DbPool}, routes::{self, health, register, oauth_login, oauth_callback}};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // load config
    let config = AppConfig::from_env()?;
    tracing::info!(?config, "loaded config");

    // db
    let pool: DbPool = db::init_pool(&config.database_url)?;
    db::run_migrations(&mut pool.get().expect("db conn")).expect("migrations");

    // app state
    let state = routes::AppState::new(config.clone(), pool.clone());

    // router
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/register", post(register))
        .route("/auth/login/{provider}", get(oauth_login))
        .route("/auth/callback", get(oauth_callback))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        )
        .layer(TraceLayer::new_for_http());

    let addr: std::net::SocketAddr = config.server_addr.parse().unwrap_or(([127,0,0,1], 8080).into());
    tracing::info!(%addr, "listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
