use serde::{Deserialize, Serialize};
use tower_cookies::{Cookie, Cookies};
use time::{Duration, OffsetDateTime};

pub const SESSION_COOKIE: &str = "sid";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub user_id: String,
    pub exp: Option<i64>, // unix seconds
}

pub fn get_session(cookies: &Cookies, key: &tower_cookies::Key) -> Option<Session> {
    let c = cookies.private(key).get(SESSION_COOKIE)?;
    let val = c.value().as_bytes();
    serde_json::from_slice(val).ok()
}

pub fn set_session(
    cookies: &Cookies,
    key: &tower_cookies::Key,
    user_id: &str,
    ttl_minutes: i64,
) {
    let exp = OffsetDateTime::now_utc() + Duration::minutes(ttl_minutes);
    let s = Session { user_id: user_id.to_string(), exp: Some(exp.unix_timestamp()) };
    if let Ok(payload) = serde_json::to_vec(&s) {
        let mut cookie = Cookie::new(SESSION_COOKIE, String::from_utf8_lossy(&payload).to_string());
        cookie.set_path("/");
        cookie.set_http_only(true);
        cookie.set_same_site(tower_cookies::cookie::SameSite::Lax);
        cookie.set_secure(is_https());
        cookie.set_max_age(time::Duration::minutes(ttl_minutes));
        cookies.private(key).add(cookie);
    }
}

pub fn clear_session(cookies: &Cookies, key: &tower_cookies::Key) {
    let mut base = Cookie::new(SESSION_COOKIE, "");
    base.set_path("/");
    cookies.remove(base.clone());
    cookies.private(key).remove(base);
}

pub(crate) fn is_https() -> bool {
    // Use environment hint; default to false for local dev
    matches!(std::env::var("APP_FORCE_SECURE").as_deref(), Ok("1") | Ok("true") | Ok("yes"))
}
