use serde::{Deserialize, Serialize};
use tower_cookies::{Cookie, Cookies};
use time::{Duration, OffsetDateTime};

pub const SESSION_COOKIE: &str = "sid";
pub const RETURN_TO_COOKIE: &str = "return_to";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub user_id: String,
    pub exp: Option<i64>, // unix seconds
}

pub fn get_session(cookies: &Cookies, key: &tower_cookies::Key) -> Option<Session> {
    let c = cookies.private(key).get(SESSION_COOKIE)?;
    let val = c.value().as_bytes();
    let session: Session = serde_json::from_slice(val).ok()?;
    if let Some(exp) = session.exp {
        if OffsetDateTime::now_utc().unix_timestamp() > exp {
            return None;
        }
    }
    Some(session)
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

pub fn set_login_return_to(cookies: &Cookies, path: &str) {
    let mut cookie = Cookie::new(RETURN_TO_COOKIE, path.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(tower_cookies::cookie::SameSite::Lax);
    cookie.set_secure(is_https());
    cookie.set_max_age(Duration::minutes(10));
    cookies.add(cookie);
}

pub fn take_login_return_to(cookies: &Cookies) -> Option<String> {
    let value = cookies.get(RETURN_TO_COOKIE).map(|c| c.value().to_string());
    if value.is_some() {
        let mut cookie = Cookie::new(RETURN_TO_COOKIE, "");
        cookie.set_path("/");
        cookies.remove(cookie);
    }
    value
}

pub(crate) fn is_https() -> bool {
    // Use environment hint; default to false for local dev
    matches!(std::env::var("APP_FORCE_SECURE").as_deref(), Ok("1") | Ok("true") | Ok("yes"))
}
