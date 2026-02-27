use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
}

#[cw_serde]
#[derive(Default)]
pub struct ExpectedMeasurements {
    pub mr_td: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr0: Option<String>,
    pub check_rtmr0: bool,
}

#[cw_serde]
#[derive(Default)]
pub struct ExpectedEvents {
    pub compose_hash: Option<String>,
    pub os_image_hash: Option<String>,
}

#[cw_serde]
pub struct VerificationRecord {
    pub quote_verified: bool,
    pub rtmr3_verified: bool,
    pub measurements_verified: bool,
    pub events_verified: bool,
    pub all_passed: bool,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
    pub mr_td: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
    pub report_data: String,
    pub response_body_verified: bool,
    pub response_body_hash: Option<String>,
    pub mismatches: Vec<String>,
    pub verifier: Addr,
    pub block_height: u64,
    pub block_time: u64,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const EXPECTED_MEASUREMENTS: Item<ExpectedMeasurements> = Item::new("expected_measurements");
pub const EXPECTED_EVENTS: Item<ExpectedEvents> = Item::new("expected_events");
pub const VERIFICATIONS: Map<&str, VerificationRecord> = Map::new("verifications");
