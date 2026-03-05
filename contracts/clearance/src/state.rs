use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary};
use cw_storage_plus::Item;

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub nft_contract: Addr,
    pub attestation_contract: Addr,
}

#[cw_serde]
pub struct PendingProof {
    pub sender: Addr,
    pub response_body: Binary,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const BADGE_COUNT: Item<u64> = Item::new("badge_count");
pub const PENDING_PROOF: Item<PendingProof> = Item::new("pending_proof");
