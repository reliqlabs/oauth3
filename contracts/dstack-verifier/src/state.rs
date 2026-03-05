use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
}

/// Expected measurement values for TDX quote verification.
/// `None` fields are not checked during verification.
#[cw_serde]
#[derive(Default)]
pub struct ExpectedConfig {
    pub mr_td: Option<String>,
    pub rt_mr0: Option<String>,
    pub rt_mr1: Option<String>,
    pub rt_mr2: Option<String>,
    pub rt_mr3: Option<String>,
    pub report_data: Option<String>,
}

#[cw_serde]
pub struct VerificationRecord {
    pub verified: bool,
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub mr_td: String,
    pub rt_mr0: String,
    pub rt_mr1: String,
    pub rt_mr2: String,
    pub rt_mr3: String,
    pub report_data: String,
    pub verifier: Addr,
    pub block_height: u64,
    pub block_time: u64,
    pub config_match: bool,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const EXPECTED_CONFIG: Item<ExpectedConfig> = Item::new("expected_config");
pub const VERIFICATIONS: Map<&str, VerificationRecord> = Map::new("verifications");
