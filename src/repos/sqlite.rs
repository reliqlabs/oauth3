use std::sync::Arc;

use async_trait::async_trait;
use diesel::prelude::*;
use diesel::OptionalExtension;

use crate::models::{
    identity::{NewIdentity, UserIdentity},
    user::{NewUser, User},
    provider::Provider,
};
use crate::repos::AccountsRepo;
use crate::schema::{user_identities, users, oauth_providers};

pub struct SqliteAccountsRepo {
    pool: crate::db::sqlite::SqlitePool,
}

impl SqliteAccountsRepo {
    pub fn new(pool: crate::db::sqlite::SqlitePool) -> Arc<Self> {
        Arc::new(Self { pool })
    }
}

#[async_trait]
impl AccountsRepo for SqliteAccountsRepo {
    async fn find_user_by_identity(&self, provider: &str, subject: &str) -> anyhow::Result<Option<User>> {
        let provider = provider.to_string();
        let subject = subject.to_string();
        let pool = self.pool.clone();
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<User>> {
            let mut conn = pool.get()?;
            use user_identities::dsl as ui;
            let uid: Option<String> = ui::user_identities
                .filter(ui::provider_key.eq(&provider))
                .filter(ui::subject.eq(&subject))
                .select(ui::user_id)
                .first::<String>(&mut conn)
                .optional()?;
            if let Some(user_id) = uid {
                let u = users::table.find(user_id).first::<User>(&mut conn).optional()?;
                Ok(u)
            } else {
                Ok(None)
            }
        })
        .await?;
        res
    }

    async fn create_user_and_link(&self, new_user: NewUser<'_>, new_identity: NewIdentity<'_>) -> anyhow::Result<User> {
        let pool = self.pool.clone();
        let new_user = (new_user.id.to_string(), new_user.primary_email.map(|s| s.to_string()), new_user.display_name.map(|s| s.to_string()));
        let new_identity = (
            new_identity.id.to_string(),
            new_identity.user_id.to_string(),
            new_identity.provider_key.to_string(),
            new_identity.subject.to_string(),
            new_identity.email.map(|s| s.to_string()),
            new_identity.access_token.map(|s| s.to_string()),
            new_identity.refresh_token.map(|s| s.to_string()),
            new_identity.expires_at.map(|s| s.to_string()),
            new_identity.claims.map(|s| s.to_string()),
        );
        let user = tokio::task::spawn_blocking(move || -> anyhow::Result<User> {
            let mut conn = pool.get()?;
            conn.immediate_transaction(|conn| {
                diesel::insert_into(users::table)
                    .values(&crate::models::user::NewUser {
                        id: &new_user.0,
                        primary_email: new_user.1.as_deref(),
                        display_name: new_user.2.as_deref(),
                    })
                    .execute(conn)?;
                diesel::insert_into(user_identities::table)
                    .values(&crate::models::identity::NewIdentity {
                        id: &new_identity.0,
                        user_id: &new_identity.1,
                        provider_key: &new_identity.2,
                        subject: &new_identity.3,
                        email: new_identity.4.as_deref(),
                        access_token: new_identity.5.as_deref(),
                        refresh_token: new_identity.6.as_deref(),
                        expires_at: new_identity.7.as_deref(),
                        claims: new_identity.8.as_deref(),
                    })
                    .execute(conn)?;
                let u = users::table.find(&new_user.0).first::<User>(conn)?;
                Ok(u)
            })
        })
        .await??;
        Ok(user)
    }

    async fn list_identities(&self, user_id: &str) -> anyhow::Result<Vec<UserIdentity>> {
        let user_id = user_id.to_string();
        let pool = self.pool.clone();
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<UserIdentity>> {
            let mut conn = pool.get()?;
            use user_identities::dsl as ui;
            let rows = ui::user_identities
                .filter(ui::user_id.eq(&user_id))
                .order(ui::linked_at.asc())
                .load::<UserIdentity>(&mut conn)?;
            Ok(rows)
        })
        .await?;
        res
    }

    async fn list_identities_by_subject(&self, provider_key: &str, subject: &str) -> anyhow::Result<Option<UserIdentity>> {
        let provider_key = provider_key.to_string();
        let subject = subject.to_string();
        let pool = self.pool.clone();
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<UserIdentity>> {
            let mut conn = pool.get()?;
            use user_identities::dsl as ui;
            let row = ui::user_identities
                .filter(ui::provider_key.eq(&provider_key))
                .filter(ui::subject.eq(&subject))
                .first::<UserIdentity>(&mut conn)
                .optional()?;
            Ok(row)
        })
        .await?;
        res
    }

    async fn link_identity(&self, new_identity: NewIdentity<'_>) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        let new_identity = (
            new_identity.id.to_string(),
            new_identity.user_id.to_string(),
            new_identity.provider_key.to_string(),
            new_identity.subject.to_string(),
            new_identity.email.map(|s| s.to_string()),
            new_identity.access_token.map(|s| s.to_string()),
            new_identity.refresh_token.map(|s| s.to_string()),
            new_identity.expires_at.map(|s| s.to_string()),
            new_identity.claims.map(|s| s.to_string()),
        );
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(user_identities::table)
                .values(&crate::models::identity::NewIdentity {
                    id: &new_identity.0,
                    user_id: &new_identity.1,
                    provider_key: &new_identity.2,
                    subject: &new_identity.3,
                    email: new_identity.4.as_deref(),
                    access_token: new_identity.5.as_deref(),
                    refresh_token: new_identity.6.as_deref(),
                    expires_at: new_identity.7.as_deref(),
                    claims: new_identity.8.as_deref(),
                })
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn update_identity_tokens(&self, provider_key: &str, subject: &str, access_token: &str, refresh_token: Option<&str>, expires_at: Option<&str>) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        let provider_key = provider_key.to_string();
        let subject = subject.to_string();
        let access_token = access_token.to_string();
        let refresh_token = refresh_token.map(|s| s.to_string());
        let expires_at = expires_at.map(|s| s.to_string());

        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            use user_identities::dsl as ui;
            diesel::update(
                ui::user_identities
                    .filter(ui::provider_key.eq(&provider_key))
                    .filter(ui::subject.eq(&subject))
            )
            .set((
                ui::access_token.eq(&access_token),
                ui::refresh_token.eq(&refresh_token),
                ui::expires_at.eq(&expires_at),
            ))
            .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn unlink_identity_by_provider(&self, user_id: &str, provider_key: &str) -> anyhow::Result<usize> {
        let user_id = user_id.to_string();
        let provider_key = provider_key.to_string();
        let pool = self.pool.clone();
        let n = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            let mut conn = pool.get()?;
            use user_identities::dsl as ui;
            let res = diesel::delete(
                ui::user_identities
                    .filter(ui::user_id.eq(&user_id))
                    .filter(ui::provider_key.eq(&provider_key)),
            )
            .execute(&mut conn)?;
            Ok(res as usize)
        })
        .await??;
        Ok(n)
    }

    async fn count_identities(&self, user_id: &str) -> anyhow::Result<i64> {
        let user_id = user_id.to_string();
        let pool = self.pool.clone();
        let n = tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
            let mut conn = pool.get()?;
            use user_identities::dsl as ui;
            use diesel::dsl::count_star;
            let n: i64 = ui::user_identities
                .filter(ui::user_id.eq(&user_id))
                .select(count_star())
                .first(&mut conn)?;
            Ok(n)
        })
        .await??;
        Ok(n)
    }

    async fn list_providers(&self) -> anyhow::Result<Vec<Provider>> {
        let pool = self.pool.clone();
        let providers = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Provider>> {
            let mut conn = pool.get()?;
            let rows = oauth_providers::table
                .filter(oauth_providers::is_enabled.eq(1))
                .order(oauth_providers::name.asc())
                .load::<Provider>(&mut conn)?;
            Ok(rows)
        })
        .await??;
        Ok(providers)
    }

    async fn get_provider(&self, id: &str) -> anyhow::Result<Option<Provider>> {
        let id = id.to_string();
        let pool = self.pool.clone();
        let provider = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Provider>> {
            let mut conn = pool.get()?;
            let p = oauth_providers::table
                .find(id)
                .first::<Provider>(&mut conn)
                .optional()?;
            Ok(p)
        })
        .await??;
        Ok(provider)
    }

    async fn save_provider(&self, provider: Provider) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(oauth_providers::table)
                .values(&provider)
                .on_conflict(oauth_providers::id)
                .do_update()
                .set(&provider)
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }
}
