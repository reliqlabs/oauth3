use dotenvy::dotenv;
use std::env;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub server_addr: String,
    pub database_url: String,
    pub jwt_secret: String,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let _ = dotenv();
        let server_addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "oauth3.db".to_string());
        let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "CHANGE_ME_DEVELOPMENT_SECRET".to_string());

        Ok(Self {
            server_addr,
            database_url,
            jwt_secret,
        })
    }
}