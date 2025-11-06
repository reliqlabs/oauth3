use diesel::r2d2::{self, ConnectionManager};
use diesel::{sqlite::SqliteConnection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

pub type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub fn init_pool(database_url: &str) -> anyhow::Result<DbPool> {
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .max_size(8)
        .build(manager)?;
    Ok(pool)
}

pub fn run_migrations(conn: &mut SqliteConnection) -> anyhow::Result<()> {
    conn
        .run_pending_migrations(MIGRATIONS)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!(e))
}
