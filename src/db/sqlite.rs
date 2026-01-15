use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;

pub type SqlitePool = Pool<ConnectionManager<SqliteConnection>>;

pub fn make_pool(database_url: &str) -> anyhow::Result<SqlitePool> {
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = Pool::builder().max_size(8).build(manager)?;
    Ok(pool)
}
