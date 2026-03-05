use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
use sha2::{Digest, Sha256};

use crate::error::{ContractError, ContractResult};
use crate::msg::{EventLogEntry, ExpectedEventsMsg, ExpectedMeasurementsMsg};
use crate::rtmr;
use crate::state::{
    ExpectedEvents, ExpectedMeasurements, VerificationRecord, CONFIG, EXPECTED_EVENTS,
    EXPECTED_MEASUREMENTS, VERIFICATIONS,
};

pub fn set_expected_measurements(
    deps: DepsMut,
    info: MessageInfo,
    msg: ExpectedMeasurementsMsg,
) -> ContractResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized);
    }

    EXPECTED_MEASUREMENTS.save(
        deps.storage,
        &ExpectedMeasurements {
            mr_td: msg.mr_td,
            rtmr1: msg.rtmr1,
            rtmr2: msg.rtmr2,
            rtmr0: msg.rtmr0,
            check_rtmr0: msg.check_rtmr0,
        },
    )?;

    Ok(Response::new().add_attribute("action", "set_expected_measurements"))
}

pub fn set_expected_events(
    deps: DepsMut,
    info: MessageInfo,
    msg: ExpectedEventsMsg,
) -> ContractResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized);
    }

    EXPECTED_EVENTS.save(
        deps.storage,
        &ExpectedEvents {
            compose_hash: msg.compose_hash,
            os_image_hash: msg.os_image_hash,
        },
    )?;

    Ok(Response::new().add_attribute("action", "set_expected_events"))
}

pub fn verify_attestation(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    quote_bytes: &[u8],
    collateral_bytes: &[u8],
    event_log: Vec<EventLogEntry>,
    response_body: Option<&[u8]>,
) -> ContractResult<Response> {
    let quote_hash = hex::encode(Sha256::digest(quote_bytes));

    if VERIFICATIONS.has(deps.storage, &quote_hash) {
        return Err(ContractError::AlreadyVerified);
    }

    // 1. Verify quote via dcap-qvl
    let collateral: dcap_qvl::QuoteCollateralV3 =
        serde_json::from_slice(collateral_bytes).map_err(|e| ContractError::InvalidCollateral {
            reason: e.to_string(),
        })?;

    let now = env.block.time.seconds();
    let verified_report =
        dcap_qvl::verify::cosmwasm::verify(quote_bytes, &collateral, now).map_err(|e| {
            ContractError::VerificationFailed {
                reason: format!("{:#}", e),
            }
        })?;

    // 2. Extract TDX report
    let td_report = verified_report
        .report
        .as_td10()
        .ok_or(ContractError::NotTdxQuote)?;

    let mr_td = hex::encode(td_report.mr_td);
    let rtmr0 = hex::encode(td_report.rt_mr0);
    let rtmr1 = hex::encode(td_report.rt_mr1);
    let rtmr2 = hex::encode(td_report.rt_mr2);
    let rtmr3 = hex::encode(td_report.rt_mr3);
    let report_data = hex::encode(td_report.report_data);

    let mut mismatches = Vec::new();

    // 3. Replay RTMR3 from event log
    let replayed = rtmr::replay_rtmr3(&event_log);
    let replayed_hex = hex::encode(replayed);
    let rtmr3_verified = rtmr3 == replayed_hex;
    if !rtmr3_verified {
        mismatches.push(format!(
            "rtmr3: quoted={}, replayed={}",
            rtmr3, replayed_hex
        ));
    }

    // 4. Check measurements against expected
    let measurements_verified = match EXPECTED_MEASUREMENTS.may_load(deps.storage)? {
        Some(expected) => {
            let before = mismatches.len();
            check_measurement(&expected.mr_td, &mr_td, "mr_td", &mut mismatches);
            check_measurement(&expected.rtmr1, &rtmr1, "rtmr1", &mut mismatches);
            check_measurement(&expected.rtmr2, &rtmr2, "rtmr2", &mut mismatches);
            if expected.check_rtmr0 {
                if let Some(ref exp_rtmr0) = expected.rtmr0 {
                    check_measurement(exp_rtmr0, &rtmr0, "rtmr0", &mut mismatches);
                }
            }
            mismatches.len() == before
        }
        None => true,
    };

    // 5. Check deterministic events
    let events_verified = match EXPECTED_EVENTS.may_load(deps.storage)? {
        Some(expected) => {
            let event_mismatches = rtmr::validate_events(&event_log, &expected);
            mismatches.extend(event_mismatches.iter().cloned());
            event_mismatches.is_empty()
        }
        None => true,
    };

    // 6. Verify response body against report_data (optional oracle check)
    //
    // The TEE middleware puts data into report_data as follows:
    //   body > 64 bytes:  report_data[..32] = SHA256(body), report_data[32..] = 0
    //   body <= 64 bytes: report_data = body zero-padded to 64 bytes
    let (response_body_verified, response_body_hash) = match response_body {
        Some(body) => {
            let expected_report_data = if body.len() > 64 {
                let hash = Sha256::digest(body);
                let mut padded = [0u8; 64];
                padded[..32].copy_from_slice(&hash);
                hex::encode(padded)
            } else {
                let mut padded = [0u8; 64];
                padded[..body.len()].copy_from_slice(body);
                hex::encode(padded)
            };

            let matched = report_data == expected_report_data;
            if !matched {
                mismatches.push(format!(
                    "response_body: report_data mismatch (expected={}, actual={})",
                    expected_report_data, report_data
                ));
            }

            let body_hash = hex::encode(Sha256::digest(body));
            (matched, Some(body_hash))
        }
        None => (true, None),
    };

    let all_passed =
        rtmr3_verified && measurements_verified && events_verified && response_body_verified;

    let record = VerificationRecord {
        quote_verified: true,
        rtmr3_verified,
        measurements_verified,
        events_verified,
        all_passed,
        tcb_status: verified_report.status.clone(),
        advisory_ids: verified_report.advisory_ids.clone(),
        mr_td: mr_td.clone(),
        rtmr0: rtmr0.clone(),
        rtmr1: rtmr1.clone(),
        rtmr2: rtmr2.clone(),
        rtmr3: rtmr3.clone(),
        report_data,
        response_body_verified,
        response_body_hash,
        mismatches,
        verifier: info.sender,
        block_height: env.block.height,
        block_time: env.block.time.seconds(),
    };

    VERIFICATIONS.save(deps.storage, &quote_hash, &record)?;

    Ok(Response::new()
        .add_attribute("action", "verify_attestation")
        .add_attribute("quote_hash", &quote_hash)
        .add_attribute("tcb_status", &verified_report.status)
        .add_attribute("all_passed", all_passed.to_string())
        .add_attribute("rtmr3_verified", rtmr3_verified.to_string())
        .add_attribute("measurements_verified", measurements_verified.to_string())
        .add_attribute("events_verified", events_verified.to_string())
        .add_attribute("response_body_verified", response_body_verified.to_string()))
}

fn check_measurement(expected: &str, actual: &str, field: &str, mismatches: &mut Vec<String>) {
    if expected != actual {
        mismatches.push(format!(
            "{}: expected={}, actual={}",
            field, expected, actual
        ));
    }
}
