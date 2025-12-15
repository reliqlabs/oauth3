use diesel_migrations::{embed_migrations, EmbeddedMigrations};

// Embed all files under migrations/ (path is relative to crate root)
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[cfg(feature = "pg")]
pub async fn run_pg_migrations(conn: &mut diesel_async::AsyncPgConnection) -> anyhow::Result<()> {
    use diesel_migrations::MigrationHarness;
    // Diesel's MigrationHarness is currently sync; diesel_async provides an adapter via `RunQueryDsl` for queries,
    // but for migrations we can run them using the provided harness on the underlying connection when supported.
    // Placeholder: handled externally via CLI in dev. In production, consider a separate migrator binary.
    let _ = conn; // silence unused for now
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
