use std::sync::Arc;

use async_trait::async_trait;
use diesel::prelude::*;
use diesel::OptionalExtension;

use crate::models::{
    identity::{NewIdentity, UserIdentity},
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
            new_identity.scopes.map(|s| s.to_string()),
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
                        scopes: new_identity.8.as_deref(),
                        claims: new_identity.9.as_deref(),
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

    async fn get_user_identity(&self, user_id: &str, provider_key: &str) -> anyhow::Result<Option<UserIdentity>> {
        let user_id = user_id.to_string();
        let provider_key = provider_key.to_string();
        let pool = self.pool.clone();
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<UserIdentity>> {
            let mut conn = pool.get()?;
            use user_identities::dsl as ui;
            let row = ui::user_identities
                .filter(ui::user_id.eq(&user_id))
                .filter(ui::provider_key.eq(&provider_key))
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
            new_identity.scopes.map(|s| s.to_string()),
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
                    scopes: new_identity.8.as_deref(),
                    claims: new_identity.9.as_deref(),
                })
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn update_identity_tokens(&self, provider_key: &str, subject: &str, access_token: &str, refresh_token: Option<&str>, expires_at: Option<&str>, scopes: Option<&str>) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        let provider_key = provider_key.to_string();
        let subject = subject.to_string();
        let access_token = access_token.to_string();
        let refresh_token = refresh_token.map(|s| s.to_string());
        let expires_at = expires_at.map(|s| s.to_string());
        let scopes = scopes.map(|s| s.to_string());
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
                ui::scopes.eq(&scopes),
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

    async fn create_api_key(&self, api_key: ApiKey) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(api_keys::table)
                .values(&api_key)
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn list_api_keys(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        let user_id = user_id.to_string();
        let pool = self.pool.clone();
        let keys = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<ApiKey>> {
            let mut conn = pool.get()?;
            let rows = api_keys::table
                .filter(api_keys::user_id.eq(&user_id))
                .filter(api_keys::deleted_at.is_null())
                .order(api_keys::created_at.desc())
                .load::<ApiKey>(&mut conn)?;
            Ok(rows)
        })
        .await??;
        Ok(keys)
    }

    async fn get_api_key_by_hash(&self, key_hash: &str) -> anyhow::Result<Option<ApiKey>> {
        let key_hash = key_hash.to_string();
        let pool = self.pool.clone();
        let key = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<ApiKey>> {
            let mut conn = pool.get()?;
            let k = api_keys::table
                .filter(api_keys::key_hash.eq(&key_hash))
                .filter(api_keys::deleted_at.is_null())
                .first::<ApiKey>(&mut conn)
                .optional()?;
            Ok(k)
        })
        .await??;
        Ok(key)
    }

    async fn update_api_key_last_used(&self, id: &str) -> anyhow::Result<()> {
        let id = id.to_string();
        let pool = self.pool.clone();
        let now = time::OffsetDateTime::now_utc().to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::update(api_keys::table.find(&id))
                .set(api_keys::last_used_at.eq(&now))
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn soft_delete_api_key(&self, id: &str, user_id: &str) -> anyhow::Result<()> {
        let id = id.to_string();
        let user_id = user_id.to_string();
        let pool = self.pool.clone();
        let now = time::OffsetDateTime::now_utc().to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::update(
                api_keys::table
                    .filter(api_keys::id.eq(&id))
                    .filter(api_keys::user_id.eq(&user_id))
            )
            .set(api_keys::deleted_at.eq(&now))
            .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn list_applications(&self, owner_user_id: &str) -> anyhow::Result<Vec<Application>> {
        let owner_user_id = owner_user_id.to_string();
        let pool = self.pool.clone();
        let apps = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Application>> {
            let mut conn = pool.get()?;
            let rows = applications::table
                .filter(applications::owner_user_id.eq(&owner_user_id))
                .order(applications::created_at.desc())
                .load::<Application>(&mut conn)?;
            Ok(rows)
        })
        .await??;
        Ok(apps)
    }

    async fn get_application(&self, id: &str) -> anyhow::Result<Option<Application>> {
        let id = id.to_string();
        let pool = self.pool.clone();
        let app = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Application>> {
            let mut conn = pool.get()?;
            let row = applications::table
                .find(&id)
                .first::<Application>(&mut conn)
                .optional()?;
            Ok(row)
        })
        .await??;
        Ok(app)
    }

    async fn save_application(&self, app: Application) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(applications::table)
                .values(&app)
                .on_conflict(applications::id)
                .do_update()
                .set(&app)
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn list_app_redirect_uris(&self, app_id: &str) -> anyhow::Result<Vec<AppRedirectUri>> {
        let app_id = app_id.to_string();
        let pool = self.pool.clone();
        let rows = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<AppRedirectUri>> {
            let mut conn = pool.get()?;
            let rows = app_redirect_uris::table
                .filter(app_redirect_uris::app_id.eq(&app_id))
                .order(app_redirect_uris::created_at.asc())
                .load::<AppRedirectUri>(&mut conn)?;
            Ok(rows)
        })
        .await??;
        Ok(rows)
    }

    async fn add_app_redirect_uri(&self, redirect_uri: AppRedirectUri) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(app_redirect_uris::table)
                .values(&redirect_uri)
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn remove_app_redirect_uri(&self, app_id: &str, redirect_uri: &str) -> anyhow::Result<usize> {
        let app_id = app_id.to_string();
        let redirect_uri = redirect_uri.to_string();
        let pool = self.pool.clone();
        let rows = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            let mut conn = pool.get()?;
            let n = diesel::delete(
                app_redirect_uris::table
                    .filter(app_redirect_uris::app_id.eq(&app_id))
                    .filter(app_redirect_uris::redirect_uri.eq(&redirect_uri))
            )
            .execute(&mut conn)?;
            Ok(n as usize)
        })
        .await??;
        Ok(rows)
    }

    async fn get_user_consent(&self, user_id: &str, app_id: &str) -> anyhow::Result<Option<UserConsent>> {
        let user_id = user_id.to_string();
        let app_id = app_id.to_string();
        let pool = self.pool.clone();
        let row = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<UserConsent>> {
            let mut conn = pool.get()?;
            let row = user_consents::table
                .filter(user_consents::user_id.eq(&user_id))
                .filter(user_consents::app_id.eq(&app_id))
                .first::<UserConsent>(&mut conn)
                .optional()?;
            Ok(row)
        })
        .await??;
        Ok(row)
    }

    async fn list_user_consents(&self, user_id: &str) -> anyhow::Result<Vec<UserConsent>> {
        let user_id = user_id.to_string();
        let pool = self.pool.clone();
        let rows = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<UserConsent>> {
            let mut conn = pool.get()?;
            let rows = user_consents::table
                .filter(user_consents::user_id.eq(&user_id))
                .order(user_consents::created_at.desc())
                .load::<UserConsent>(&mut conn)?;
            Ok(rows)
        })
        .await??;
        Ok(rows)
    }

    async fn save_user_consent(&self, consent: UserConsent) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(user_consents::table)
                .values(&consent)
                .on_conflict((user_consents::user_id, user_consents::app_id))
                .do_update()
                .set((
                    user_consents::scopes.eq(&consent.scopes),
                    user_consents::revoked_at.eq(&consent.revoked_at),
                ))
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn revoke_user_consent(&self, user_id: &str, app_id: &str) -> anyhow::Result<()> {
        let user_id = user_id.to_string();
        let app_id = app_id.to_string();
        let pool = self.pool.clone();
        let now = time::OffsetDateTime::now_utc().to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::update(
                user_consents::table
                    .filter(user_consents::user_id.eq(&user_id))
                    .filter(user_consents::app_id.eq(&app_id))
            )
            .set(user_consents::revoked_at.eq(&now))
            .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn create_oauth_code(&self, code: OAuthCode) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(oauth_codes::table)
                .values(&code)
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn consume_oauth_code(&self, code_hash: &str) -> anyhow::Result<Option<OAuthCode>> {
        let code_hash = code_hash.to_string();
        let pool = self.pool.clone();
        let now = time::OffsetDateTime::now_utc().to_string();
        let row = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<OAuthCode>> {
            let mut conn = pool.get()?;
            conn.immediate_transaction(|conn| {
                use oauth_codes::dsl as oc;
                let row = oc::oauth_codes
                    .filter(oc::code_hash.eq(&code_hash))
                    .filter(oc::consumed_at.is_null())
                    .first::<OAuthCode>(conn)
                    .optional()?;
                if row.is_some() {
                    diesel::update(oc::oauth_codes.filter(oc::code_hash.eq(&code_hash)))
                        .set(oc::consumed_at.eq(&now))
                        .execute(conn)?;
                }
                Ok(row)
            })
        })
        .await??;
        Ok(row)
    }

    async fn create_app_access_token(&self, token: AppAccessToken) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(app_access_tokens::table)
                .values(&token)
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn get_app_access_token_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<AppAccessToken>> {
        let token_hash = token_hash.to_string();
        let pool = self.pool.clone();
        let row = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<AppAccessToken>> {
            let mut conn = pool.get()?;
            let row = app_access_tokens::table
                .filter(app_access_tokens::token_hash.eq(&token_hash))
                .filter(app_access_tokens::revoked_at.is_null())
                .first::<AppAccessToken>(&mut conn)
                .optional()?;
            Ok(row)
        })
        .await??;
        Ok(row)
    }

    async fn update_app_access_token_last_used(&self, id: &str) -> anyhow::Result<()> {
        let id = id.to_string();
        let pool = self.pool.clone();
        let now = time::OffsetDateTime::now_utc().to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::update(app_access_tokens::table.find(&id))
                .set(app_access_tokens::last_used_at.eq(&now))
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn revoke_app_access_token(&self, id: &str) -> anyhow::Result<()> {
        let id = id.to_string();
        let pool = self.pool.clone();
        let now = time::OffsetDateTime::now_utc().to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::update(app_access_tokens::table.find(&id))
                .set(app_access_tokens::revoked_at.eq(&now))
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn create_app_refresh_token(&self, token: AppRefreshToken) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(app_refresh_tokens::table)
                .values(&token)
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn get_app_refresh_token_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<AppRefreshToken>> {
        let token_hash = token_hash.to_string();
        let pool = self.pool.clone();
        let row = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<AppRefreshToken>> {
            let mut conn = pool.get()?;
            let row = app_refresh_tokens::table
                .filter(app_refresh_tokens::token_hash.eq(&token_hash))
                .filter(app_refresh_tokens::revoked_at.is_null())
                .first::<AppRefreshToken>(&mut conn)
                .optional()?;
            Ok(row)
        })
        .await??;
        Ok(row)
    }

    async fn revoke_app_refresh_token(&self, id: &str, replaced_by_id: Option<&str>) -> anyhow::Result<()> {
        let id = id.to_string();
        let replaced_by_id = replaced_by_id.map(|s| s.to_string());
        let pool = self.pool.clone();
        let now = time::OffsetDateTime::now_utc().to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get()?;
            diesel::update(app_refresh_tokens::table.find(&id))
                .set((
                    app_refresh_tokens::revoked_at.eq(&now),
                    app_refresh_tokens::replaced_by_id.eq(&replaced_by_id),
                ))
                .execute(&mut conn)?;
            Ok(())
        })
        .await??;
        Ok(())
    }
}
