use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
    Ok(hash)
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    let parsed = PasswordHash::new(hash);
    if parsed.is_err() { return false; }
    let parsed = parsed.unwrap();
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

pub fn create_jwt(sub: &str, secret: &str, ttl_minutes: i64) -> anyhow::Result<String> {
    let exp = (Utc::now() + Duration::minutes(ttl_minutes)).timestamp() as usize;
    let claims = Claims { sub: sub.to_string(), exp };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))?;
    Ok(token)
}
