use axum::{Router, routing::{get, post}};
use oauth3::{config::AppConfig, db, db::DbPool, routes, routes::AppState};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;
use tempfile::TempDir;

pub struct TestDb {
    pub _dir: TempDir,
    pub path: String,
    pub pool: DbPool,
}

pub fn init_test_db() -> anyhow::Result<TestDb> {
    let dir = TempDir::new()?;
    let db_path = dir.path().join("test.sqlite");
    let path_str = db_path.display().to_string();

    // Small pool to reduce SQLite locking contention
    let manager = ConnectionManager::<SqliteConnection>::new(path_str.clone());
    let pool: Pool<ConnectionManager<SqliteConnection>> = Pool::builder().max_size(2).build(manager)?;

    // Run embedded migrations
    {
        let mut conn = pool.get()?;
        db::run_migrations(&mut conn)?;
    }

    Ok(TestDb { _dir: dir, path: path_str, pool })
}

pub fn build_test_app(config: AppConfig, pool: DbPool) -> Router {
    let state = AppState::new(config, pool);
    Router::new()
        .route("/health", get(routes::health))
        .route("/api/register", post(routes::register))
        .route("/auth/login/{provider}", get(routes::oauth_login))
        .route("/auth/callback", get(routes::oauth_callback))
        .with_state(state)
}