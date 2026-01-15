use diesel_async::{pooled_connection::bb8::Pool, pooled_connection::AsyncDieselConnectionManager, AsyncPgConnection};

pub type PgPool = Pool<AsyncPgConnection>;

pub async fn make_pool(database_url: &str) -> anyhow::Result<PgPool> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
    let pool = Pool::builder().max_size(10).build(manager).await?;
    Ok(pool)
}
