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
    use diesel::RunQueryDsl;
    
    println!("Running SQLite migrations...");
    
    // Explicitly add missing columns to user_identities if they don't exist
    // This is a workaround for why the embedded migrations seem to be outdated in some environments
    let _ = diesel::sql_query("ALTER TABLE user_identities ADD COLUMN access_token TEXT").execute(conn);
    let _ = diesel::sql_query("ALTER TABLE user_identities ADD COLUMN refresh_token TEXT").execute(conn);
    let _ = diesel::sql_query("ALTER TABLE user_identities ADD COLUMN expires_at TEXT").execute(conn);

    let versions = conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("SQLite migration error: {}", e))?;
    if versions.is_empty() {
        println!("No pending SQLite migrations.");
    } else {
        for v in versions {
            println!("Applied SQLite migration: {}", v);
        }
    }
    
    // Debug: check table schema
    use diesel::sql_query;
    #[derive(diesel::QueryableByName)]
    struct TableInfo {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }
    let cols: Vec<TableInfo> = sql_query("PRAGMA table_info(user_identities)").load(conn)?;
    println!("Columns in user_identities: {:?}", cols.iter().map(|c| &c.name).collect::<Vec<_>>());
    
    Ok(())
}
