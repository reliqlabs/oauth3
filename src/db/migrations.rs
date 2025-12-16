use diesel_migrations::{embed_migrations, EmbeddedMigrations};

// Embed all files under migrations/ (path is relative to crate root)
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[cfg(feature = "pg")]
pub fn run_pg_migrations_sync(db_url: &str) -> anyhow::Result<()> {
    use diesel::prelude::*;
    use diesel_migrations::MigrationHarness;

    let mut conn = diesel::PgConnection::establish(db_url)?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
    Ok(())
}

#[cfg(feature = "sqlite")]
pub fn run_sqlite_migrations(conn: &mut diesel::sqlite::SqliteConnection) -> anyhow::Result<()> {
    use diesel_migrations::MigrationHarness;
    let res = conn.run_pending_migrations(MIGRATIONS);
    match res {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::anyhow!(e.to_string())),
    }
}
