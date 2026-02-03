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
    api_key::ApiKey,
    application::Application,
    app_redirect_uri::AppRedirectUri,
    consent::UserConsent,
    oauth_code::OAuthCode,
    app_token::{AppAccessToken, AppRefreshToken},
};
use crate::repos::AccountsRepo;
use crate::schema::{
    user_identities,
    users,
    oauth_providers,
    api_keys,
    applications,
    app_redirect_uris,
    user_consents,
    oauth_codes,
    app_access_tokens,
    app_refresh_tokens,
};

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

    async fn list_identities_by_subject(&self, provider_key: &str, subject: &str) -> anyhow::Result<Option<crate::models::identity::UserIdentity>> {
        use user_identities::dsl as ui;
        let mut conn = self.pool.get().await?;
        let row = ui::user_identities
            .filter(ui::provider_key.eq(provider_key))
            .filter(ui::subject.eq(subject))
            .first::<crate::models::identity::UserIdentity>(&mut conn)
            .await
            .optional()?;
        Ok(row)
    }

    async fn get_user_identity(&self, user_id: &str, provider_key: &str) -> anyhow::Result<Option<crate::models::identity::UserIdentity>> {
        use user_identities::dsl as ui;
        let mut conn = self.pool.get().await?;
        let row = ui::user_identities
            .filter(ui::user_id.eq(user_id))
            .filter(ui::provider_key.eq(provider_key))
            .first::<crate::models::identity::UserIdentity>(&mut conn)
            .await
            .optional()?;
        Ok(row)
    }

    async fn link_identity(&self, new_identity: NewIdentity<'_>) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(user_identities::table)
            .values(&new_identity)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn update_identity_tokens(&self, provider_key: &str, subject: &str, access_token: &str, refresh_token: Option<&str>, expires_at: Option<&str>, scopes: Option<&str>) -> anyhow::Result<()> {
        use user_identities::dsl as ui;
        let mut conn = self.pool.get().await?;
        diesel::update(
            ui::user_identities
                .filter(ui::provider_key.eq(provider_key))
                .filter(ui::subject.eq(subject))
        )
        .set((
            ui::access_token.eq(access_token),
            ui::refresh_token.eq(refresh_token),
            ui::expires_at.eq(expires_at),
            ui::scopes.eq(scopes),
        ))
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

    async fn create_api_key(&self, api_key: ApiKey) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(api_keys::table)
            .values(&api_key)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn list_api_keys(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        let mut conn = self.pool.get().await?;
        let rows = api_keys::table
            .filter(api_keys::user_id.eq(user_id))
            .filter(api_keys::deleted_at.is_null())
            .order(api_keys::created_at.desc())
            .load::<ApiKey>(&mut conn)
            .await?;
        Ok(rows)
    }

    async fn get_api_key_by_hash(&self, key_hash: &str) -> anyhow::Result<Option<ApiKey>> {
        let mut conn = self.pool.get().await?;
        let k = api_keys::table
            .filter(api_keys::key_hash.eq(key_hash))
            .filter(api_keys::deleted_at.is_null())
            .first::<ApiKey>(&mut conn)
            .await
            .optional()?;
        Ok(k)
    }

    async fn update_api_key_last_used(&self, id: &str) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let now = time::OffsetDateTime::now_utc().to_string();
        diesel::update(api_keys::table.find(id))
            .set(api_keys::last_used_at.eq(&now))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn soft_delete_api_key(&self, id: &str, user_id: &str) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let now = time::OffsetDateTime::now_utc().to_string();
        diesel::update(
            api_keys::table
                .filter(api_keys::id.eq(id))
                .filter(api_keys::user_id.eq(user_id))
        )
        .set(api_keys::deleted_at.eq(&now))
        .execute(&mut conn)
        .await?;
        Ok(())
    }

    async fn list_applications(&self, owner_user_id: &str) -> anyhow::Result<Vec<Application>> {
        let mut conn = self.pool.get().await?;
        let rows = applications::table
            .filter(applications::owner_user_id.eq(owner_user_id))
            .order(applications::created_at.desc())
            .load::<Application>(&mut conn)
            .await?;
        Ok(rows)
    }

    async fn get_application(&self, id: &str) -> anyhow::Result<Option<Application>> {
        let mut conn = self.pool.get().await?;
        let row = applications::table
            .find(id)
            .first::<Application>(&mut conn)
            .await
            .optional()?;
        Ok(row)
    }

    async fn save_application(&self, app: Application) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(applications::table)
            .values(&app)
            .on_conflict(applications::id)
            .do_update()
            .set(&app)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn list_app_redirect_uris(&self, app_id: &str) -> anyhow::Result<Vec<AppRedirectUri>> {
        let mut conn = self.pool.get().await?;
        let rows = app_redirect_uris::table
            .filter(app_redirect_uris::app_id.eq(app_id))
            .order(app_redirect_uris::created_at.asc())
            .load::<AppRedirectUri>(&mut conn)
            .await?;
        Ok(rows)
    }

    async fn add_app_redirect_uri(&self, redirect_uri: AppRedirectUri) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(app_redirect_uris::table)
            .values(&redirect_uri)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn remove_app_redirect_uri(&self, app_id: &str, redirect_uri: &str) -> anyhow::Result<usize> {
        let mut conn = self.pool.get().await?;
        let n = diesel::delete(
            app_redirect_uris::table
                .filter(app_redirect_uris::app_id.eq(app_id))
                .filter(app_redirect_uris::redirect_uri.eq(redirect_uri))
        )
        .execute(&mut conn)
        .await?;
        Ok(n as usize)
    }

    async fn get_user_consent(&self, user_id: &str, app_id: &str) -> anyhow::Result<Option<UserConsent>> {
        let mut conn = self.pool.get().await?;
        let row = user_consents::table
            .filter(user_consents::user_id.eq(user_id))
            .filter(user_consents::app_id.eq(app_id))
            .first::<UserConsent>(&mut conn)
            .await
            .optional()?;
        Ok(row)
    }

    async fn list_user_consents(&self, user_id: &str) -> anyhow::Result<Vec<UserConsent>> {
        let mut conn = self.pool.get().await?;
        let rows = user_consents::table
            .filter(user_consents::user_id.eq(user_id))
            .order(user_consents::created_at.desc())
            .load::<UserConsent>(&mut conn)
            .await?;
        Ok(rows)
    }

    async fn save_user_consent(&self, consent: UserConsent) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(user_consents::table)
            .values(&consent)
            .on_conflict((user_consents::user_id, user_consents::app_id))
            .do_update()
            .set((
                user_consents::scopes.eq(&consent.scopes),
                user_consents::revoked_at.eq(&consent.revoked_at),
            ))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn revoke_user_consent(&self, user_id: &str, app_id: &str) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let now = time::OffsetDateTime::now_utc().to_string();
        diesel::update(
            user_consents::table
                .filter(user_consents::user_id.eq(user_id))
                .filter(user_consents::app_id.eq(app_id))
        )
        .set(user_consents::revoked_at.eq(&now))
        .execute(&mut conn)
        .await?;
        Ok(())
    }

    async fn create_oauth_code(&self, code: OAuthCode) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(oauth_codes::table)
            .values(&code)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn consume_oauth_code(&self, code_hash: &str) -> anyhow::Result<Option<OAuthCode>> {
        let code_hash = code_hash.to_string();
        let now = time::OffsetDateTime::now_utc().to_string();
        let mut conn = self.pool.get().await?;
        let row = conn
            .transaction::<Option<OAuthCode>, diesel::result::Error, _>(|conn| {
                let code_hash = code_hash.clone();
                let now = now.clone();
                Box::pin(async move {
                    use oauth_codes::dsl as oc;
                    let row = oc::oauth_codes
                        .filter(oc::code_hash.eq(&code_hash))
                        .filter(oc::consumed_at.is_null())
                        .first::<OAuthCode>(conn)
                        .await
                        .optional()?;
                    if row.is_some() {
                        diesel::update(oc::oauth_codes.filter(oc::code_hash.eq(&code_hash)))
                            .set(oc::consumed_at.eq(&now))
                            .execute(conn)
                            .await?;
                    }
                    Ok(row)
                })
            })
            .await
            .context("pg consume_oauth_code tx failed")?;
        Ok(row)
    }

    async fn create_app_access_token(&self, token: AppAccessToken) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(app_access_tokens::table)
            .values(&token)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn get_app_access_token_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<AppAccessToken>> {
        let mut conn = self.pool.get().await?;
        let row = app_access_tokens::table
            .filter(app_access_tokens::token_hash.eq(token_hash))
            .filter(app_access_tokens::revoked_at.is_null())
            .first::<AppAccessToken>(&mut conn)
            .await
            .optional()?;
        Ok(row)
    }

    async fn update_app_access_token_last_used(&self, id: &str) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let now = time::OffsetDateTime::now_utc().to_string();
        diesel::update(app_access_tokens::table.find(id))
            .set(app_access_tokens::last_used_at.eq(&now))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn revoke_app_access_token(&self, id: &str) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let now = time::OffsetDateTime::now_utc().to_string();
        diesel::update(app_access_tokens::table.find(id))
            .set(app_access_tokens::revoked_at.eq(&now))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn create_app_refresh_token(&self, token: AppRefreshToken) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::insert_into(app_refresh_tokens::table)
            .values(&token)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn get_app_refresh_token_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<AppRefreshToken>> {
        let mut conn = self.pool.get().await?;
        let row = app_refresh_tokens::table
            .filter(app_refresh_tokens::token_hash.eq(token_hash))
            .filter(app_refresh_tokens::revoked_at.is_null())
            .first::<AppRefreshToken>(&mut conn)
            .await
            .optional()?;
        Ok(row)
    }

    async fn revoke_app_refresh_token(&self, id: &str, replaced_by_id: Option<&str>) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let now = time::OffsetDateTime::now_utc().to_string();
        diesel::update(app_refresh_tokens::table.find(id))
            .set((
                app_refresh_tokens::revoked_at.eq(&now),
                app_refresh_tokens::replaced_by_id.eq(replaced_by_id),
            ))
            .execute(&mut conn)
            .await?;
        Ok(())
    }
}
