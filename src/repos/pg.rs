use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::OptionalExtension;
use diesel_async::{AsyncPgConnection, RunQueryDsl, AsyncConnection};

use crate::models::{
    identity::NewIdentity,
    user::{NewUser, User},
    provider::Provider,
};
use crate::repos::AccountsRepo;
use crate::schema::{user_identities, users, oauth_providers};

pub struct PgAccountsRepo {
    pool: crate::db::pg::PgPool,
}

impl PgAccountsRepo {
    pub fn new(pool: crate::db::pg::PgPool) -> Arc<Self> {
        Arc::new(Self { pool })
    }
}

#[async_trait]
impl AccountsRepo for PgAccountsRepo {
    async fn find_user_by_identity(&self, provider: &str, subject: &str) -> anyhow::Result<Option<User>> {
        use user_identities::dsl as ui;
        let mut conn = self.pool.get().await?;
        let uid = ui::user_identities
            .filter(ui::provider_key.eq(provider))
            .filter(ui::subject.eq(subject))
            .select(ui::user_id)
            .first::<String>(&mut conn)
            .await
            .optional()?;
        if let Some(user_id) = uid {
            let u = users::table
                .find(user_id)
                .first::<User>(&mut conn)
                .await
                .optional()?;
            Ok(u)
        } else {
            Ok(None)
        }
    }

    async fn create_user_and_link(&self, new_user: NewUser<'_>, new_identity: NewIdentity<'_>) -> anyhow::Result<User> {
        let mut conn = self.pool.get().await?;
        let user = conn
            .transaction::<User, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    diesel::insert_into(users::table)
                        .values(&new_user)
                        .execute(conn)
                        .await?;
                    diesel::insert_into(user_identities::table)
                        .values(&new_identity)
                        .execute(conn)
                        .await?;
                    let u = users::table
                        .find(new_user.id)
                        .first::<User>(conn)
                        .await?;
                    Ok(u)
                })
            })
            .await
            .context("pg create_user_and_link tx failed")?;
        Ok(user)
    }

    async fn list_identities(&self, user_id: &str) -> anyhow::Result<Vec<crate::models::identity::UserIdentity>> {
        use user_identities::dsl as ui;
        let mut conn = self.pool.get().await?;
        let rows = ui::user_identities
            .filter(ui::user_id.eq(user_id))
            .order(ui::linked_at.asc())
            .load::<crate::models::identity::UserIdentity>(&mut conn)
            .await?;
        Ok(rows)
    }

    async fn link_identity(&self, new_identity: NewIdentity<'_>) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(user_identities::table)
            .values(&new_identity)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn unlink_identity_by_provider(&self, user_id: &str, provider_key: &str) -> anyhow::Result<usize> {
        use user_identities::dsl as ui;
        let mut conn = self.pool.get().await?;
        let n = diesel::delete(
            ui::user_identities
                .filter(ui::user_id.eq(user_id))
                .filter(ui::provider_key.eq(provider_key)),
        )
        .execute(&mut conn)
        .await?;
        Ok(n as usize)
    }

    async fn count_identities(&self, user_id: &str) -> anyhow::Result<i64> {
        use user_identities::dsl as ui;
        use diesel::dsl::count_star;
        let mut conn = self.pool.get().await?;
        let n: i64 = ui::user_identities
            .filter(ui::user_id.eq(user_id))
            .select(count_star())
            .first(&mut conn)
            .await?;
        Ok(n)
    }

    async fn list_providers(&self) -> anyhow::Result<Vec<Provider>> {
        let mut conn = self.pool.get().await?;
        let rows = oauth_providers::table
            .filter(oauth_providers::is_enabled.eq(1))
            .order(oauth_providers::name.asc())
            .load::<Provider>(&mut conn)
            .await?;
        Ok(rows)
    }

    async fn get_provider(&self, id: &str) -> anyhow::Result<Option<Provider>> {
        let mut conn = self.pool.get().await?;
        let p = oauth_providers::table
            .find(id)
            .first::<Provider>(&mut conn)
            .await
            .optional()?;
        Ok(p)
    }

    async fn save_provider(&self, provider: Provider) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(oauth_providers::table)
            .values(&provider)
            .on_conflict(oauth_providers::id)
            .do_update()
            .set(&provider)
            .execute(&mut conn)
            .await?;
        Ok(())
    }
}
