use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Binary};

// ── Contract messages ──

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: String,
    pub nft_contract: String,
    pub attestation_contract: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    SubmitProof {
        quote: Binary,
        collateral: Binary,
        event_log: Vec<EventLogEntry>,
        response_body: Binary,
    },
    UpdateConfig {
        admin: Option<String>,
        nft_contract: Option<String>,
        attestation_contract: Option<String>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ConfigResponse)]
    GetConfig {},
    #[returns(BadgeCountResponse)]
    GetBadgeCount {},
}

#[cw_serde]
pub struct ConfigResponse {
    pub admin: String,
    pub nft_contract: String,
    pub attestation_contract: String,
}

#[cw_serde]
pub struct BadgeCountResponse {
    pub count: u64,
}

// ── Cross-contract types (dstack-attestation) ──

#[cw_serde]
pub struct EventLogEntry {
    pub event: String,
    pub payload: Binary,
}

#[cw_serde]
pub enum AttestationExecuteMsg {
    VerifyAttestation {
        quote: Binary,
        collateral: Binary,
        event_log: Vec<EventLogEntry>,
        response_body: Option<Binary>,
    },
}

#[cw_serde]
pub enum AttestationQueryMsg {
    GetVerification { quote_hash: String },
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

// ── Business logic types ──

#[cw_serde]
pub struct VerificationResult {
    pub address: String,
    pub clean: bool,
    pub message_count: u64,
    pub suspect: String,
    pub timestamp: u64,
}

// ── CW721 types ──

#[cw_serde]
pub enum Cw721ExecuteMsg {
    Mint {
        token_id: String,
        owner: String,
        token_uri: Option<String>,
        extension: Option<String>,
    },
}

#[cw_serde]
pub enum Cw721QueryMsg {
    Tokens {
        owner: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
}

#[cw_serde]
pub struct TokensResponse {
    pub tokens: Vec<String>,
}
