use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
use sha2::{Digest, Sha256};

use crate::error::{ContractError, ContractResult};
use crate::state::{ExpectedConfig, VerificationRecord, CONFIG, EXPECTED_CONFIG, VERIFICATIONS};

pub fn set_expected_config(
    deps: DepsMut,
    info: MessageInfo,
    mr_td: Option<String>,
    rt_mr0: Option<String>,
    rt_mr1: Option<String>,
    rt_mr2: Option<String>,
    rt_mr3: Option<String>,
    report_data: Option<String>,
) -> ContractResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized);
    }

    let expected = ExpectedConfig {
        mr_td,
        rt_mr0,
        rt_mr1,
        rt_mr2,
        rt_mr3,
        report_data,
    };
    EXPECTED_CONFIG.save(deps.storage, &expected)?;

    Ok(Response::new().add_attribute("action", "set_expected_config"))
}

pub fn verify_quote(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    quote_bytes: &[u8],
    collateral_bytes: &[u8],
) -> ContractResult<Response> {
    // SHA256 hash of quote bytes as dedup key
    let quote_hash = hex::encode(Sha256::digest(quote_bytes));

    // Check if already verified
    if VERIFICATIONS.has(deps.storage, &quote_hash) {
        return Err(ContractError::AlreadyVerified);
    }

    // Deserialize collateral
    let collateral: dcap_qvl::QuoteCollateralV3 =
        serde_json::from_slice(collateral_bytes).map_err(|e| {
            ContractError::InvalidCollateral {
                reason: e.to_string(),
            }
        })?;

    // Verify the quote using dcap-qvl (cosmwasm native backend)
    let now = env.block.time.seconds();
    let verified_report =
        dcap_qvl::verify::cosmwasm::verify(quote_bytes, &collateral, now).map_err(|e| {
            ContractError::VerificationFailed {
                reason: format!("{:#}", e),
            }
        })?;

    // Extract TDX report
    let td_report = verified_report
        .report
        .as_td10()
        .ok_or(ContractError::NotTdxQuote)?;

    let mr_td = hex::encode(td_report.mr_td);
    let rt_mr0 = hex::encode(td_report.rt_mr0);
    let rt_mr1 = hex::encode(td_report.rt_mr1);
    let rt_mr2 = hex::encode(td_report.rt_mr2);
    let rt_mr3 = hex::encode(td_report.rt_mr3);
    let report_data = hex::encode(td_report.report_data);

    // Compare against expected config
    let config_match = match EXPECTED_CONFIG.may_load(deps.storage)? {
        Some(expected) => check_config_match(&expected, &mr_td, &rt_mr0, &rt_mr1, &rt_mr2, &rt_mr3, &report_data),
        None => true, // No expected config = pass
    };

    let record = VerificationRecord {
        verified: true,
        status: verified_report.status.clone(),
        advisory_ids: verified_report.advisory_ids.clone(),
        mr_td: mr_td.clone(),
        rt_mr0: rt_mr0.clone(),
        rt_mr1: rt_mr1.clone(),
        rt_mr2: rt_mr2.clone(),
        rt_mr3: rt_mr3.clone(),
        report_data: report_data.clone(),
        verifier: info.sender,
        block_height: env.block.height,
        block_time: env.block.time.seconds(),
        config_match,
    };

    VERIFICATIONS.save(deps.storage, &quote_hash, &record)?;

    Ok(Response::new()
        .add_attribute("action", "verify_quote")
        .add_attribute("quote_hash", &quote_hash)
        .add_attribute("status", &verified_report.status)
        .add_attribute("config_match", config_match.to_string())
        .add_attribute("mr_td", &mr_td))
}

fn check_config_match(
    expected: &ExpectedConfig,
    mr_td: &str,
    rt_mr0: &str,
    rt_mr1: &str,
    rt_mr2: &str,
    rt_mr3: &str,
    report_data: &str,
) -> bool {
    check_field(&expected.mr_td, mr_td)
        && check_field(&expected.rt_mr0, rt_mr0)
        && check_field(&expected.rt_mr1, rt_mr1)
        && check_field(&expected.rt_mr2, rt_mr2)
        && check_field(&expected.rt_mr3, rt_mr3)
        && check_report_data(&expected.report_data, report_data)
}

fn check_field(expected: &Option<String>, actual: &str) -> bool {
    match expected {
        None => true,
        Some(exp) => exp == actual,
    }
}

/// Prefix comparison for report_data: expected can be shorter than actual.
fn check_report_data(expected: &Option<String>, actual: &str) -> bool {
    match expected {
        None => true,
        Some(exp) => actual.starts_with(exp.as_str()),
    }
}
