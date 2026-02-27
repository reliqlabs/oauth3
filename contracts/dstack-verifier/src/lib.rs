use getrandom::register_custom_getrandom;

// CosmWasm doesn't provide OS-level randomness. This no-op is safe because
// dcap-qvl only verifies signatures (never signs), so randomness is unused.
fn cosmwasm_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    buf.fill(0);
    Ok(())
}

register_custom_getrandom!(cosmwasm_getrandom);

pub mod contract;
pub mod error;
pub mod execute;
pub mod msg;
pub mod state;

pub const CONTRACT_NAME: &str = "crates.io:dstack-verifier-contract";
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
