use cosmwasm_std::{
    entry_point, from_json, to_json_binary, Binary, Deps, DepsMut, Env, Event, MessageInfo, Reply,
    Response, StdError, StdResult, SubMsg, WasmMsg,
};
use sha2::{Digest, Sha256};

use crate::error::ContractError;
use crate::msg::{
    AttestationExecuteMsg, AttestationQueryMsg, BadgeCountResponse, ConfigResponse,
    Cw721ExecuteMsg, Cw721QueryMsg, ExecuteMsg, InstantiateMsg, QueryMsg, TokensResponse,
    VerificationRecord, VerificationResult,
};
use crate::state::{Config, PendingProof, BADGE_COUNT, CONFIG, PENDING_PROOF};

const VERIFY_REPLY_ID: u64 = 1;
const MAX_QUOTE_AGE_SECS: u64 = 86400;
const MAX_CLOCK_DRIFT_SECS: u64 = 300;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let config = Config {
        admin: deps.api.addr_validate(&msg.admin)?,
        nft_contract: deps.api.addr_validate(&msg.nft_contract)?,
        attestation_contract: deps.api.addr_validate(&msg.attestation_contract)?,
    };
    CONFIG.save(deps.storage, &config)?;
    BADGE_COUNT.save(deps.storage, &0u64)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SubmitProof {
            quote,
            collateral,
            event_log,
            response_body,
        } => execute_submit_proof(deps, info, quote, collateral, event_log, response_body),
        ExecuteMsg::UpdateConfig {
            admin,
            nft_contract,
            attestation_contract,
        } => execute_update_config(deps, info, admin, nft_contract, attestation_contract),
    }
}

fn execute_submit_proof(
    deps: DepsMut,
    info: MessageInfo,
    quote: Binary,
    collateral: Binary,
    event_log: Vec<crate::msg::EventLogEntry>,
    response_body: Binary,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // Store pending proof for reply handler
    PENDING_PROOF.save(
        deps.storage,
        &PendingProof {
            sender: info.sender,
            response_body: response_body.clone(),
        },
    )?;

    // Build SubMsg to dstack-attestation::VerifyAttestation
    let verify_msg = WasmMsg::Execute {
        contract_addr: config.attestation_contract.to_string(),
        msg: to_json_binary(&AttestationExecuteMsg::VerifyAttestation {
            quote,
            collateral,
            event_log,
            response_body: Some(response_body),
        })?,
        funds: vec![],
    };

    Ok(Response::new()
        .add_submessage(SubMsg::reply_on_success(verify_msg, VERIFY_REPLY_ID))
        .add_attribute("action", "submit_proof"))
}

fn execute_update_config(
    deps: DepsMut,
    info: MessageInfo,
    admin: Option<String>,
    nft_contract: Option<String>,
    attestation_contract: Option<String>,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;

    if info.sender != config.admin {
        return Err(ContractError::Unauthorized);
    }

    if let Some(admin) = admin {
        config.admin = deps.api.addr_validate(&admin)?;
    }
    if let Some(nft_contract) = nft_contract {
        config.nft_contract = deps.api.addr_validate(&nft_contract)?;
    }
    if let Some(attestation_contract) = attestation_contract {
        config.attestation_contract = deps.api.addr_validate(&attestation_contract)?;
    }

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attribute("action", "update_config"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        VERIFY_REPLY_ID => handle_verify_reply(deps, env, msg),
        id => Err(ContractError::Std(StdError::msg(format!(
            "unknown reply id: {id}"
        )))),
    }
}

fn find_attr(events: &[Event], key: &str) -> Option<String> {
    events
        .iter()
        .filter(|e| e.ty == "wasm")
        .flat_map(|e| &e.attributes)
        .find(|a| a.key == key)
        .map(|a| a.value.clone())
}

fn handle_verify_reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    let pending = PENDING_PROOF
        .load(deps.storage)
        .map_err(|_| ContractError::NoPendingProof)?;

    // Extract quote_hash from SubMsg response events
    let events = msg
        .result
        .into_result()
        .map_err(|e| ContractError::AttestationFailed(e))?
        .events;

    let quote_hash = find_attr(&events, "quote_hash")
        .ok_or_else(|| ContractError::AttestationFailed("missing quote_hash in events".into()))?;

    let config = CONFIG.load(deps.storage)?;

    // Query dstack-attestation for the full verification record
    let record: VerificationRecord = deps.querier.query_wasm_smart(
        config.attestation_contract.to_string(),
        &AttestationQueryMsg::GetVerification {
            quote_hash: quote_hash.clone(),
        },
    )?;

    // Verify attestation passed
    if !record.all_passed {
        return Err(ContractError::AttestationFailed(format!(
            "verification not all_passed, mismatches: {:?}",
            record.mismatches
        )));
    }
    if !record.response_body_verified {
        return Err(ContractError::AttestationFailed(
            "response_body not verified".into(),
        ));
    }

    // Verify response_body hash matches record
    let body_hash = hex::encode(Sha256::digest(pending.response_body.as_slice()));
    let record_hash = record
        .response_body_hash
        .ok_or(ContractError::ResponseBodyMismatch)?;
    if body_hash != record_hash {
        return Err(ContractError::ResponseBodyMismatch);
    }

    // Parse response_body as VerificationResult
    let verification: VerificationResult = from_json(&pending.response_body)
        .map_err(|_| ContractError::InvalidResultFormat)?;

    // Business logic checks
    if !verification.clean {
        return Err(ContractError::NotClean);
    }

    if verification.address != pending.sender.to_string() {
        return Err(ContractError::AddressMismatch);
    }

    // Freshness check
    let block_time = env.block.time.seconds();
    if block_time > verification.timestamp + MAX_QUOTE_AGE_SECS {
        return Err(ContractError::QuoteTooOld(format!(
            "{} seconds",
            block_time - verification.timestamp
        )));
    }
    if verification.timestamp > block_time + MAX_CLOCK_DRIFT_SECS {
        return Err(ContractError::TimestampInFuture);
    }

    // Check user doesn't already have a badge
    let tokens_response: TokensResponse = deps.querier.query_wasm_smart(
        config.nft_contract.to_string(),
        &Cw721QueryMsg::Tokens {
            owner: pending.sender.to_string(),
            start_after: None,
            limit: Some(1),
        },
    )?;
    if !tokens_response.tokens.is_empty() {
        return Err(ContractError::AlreadyHasBadge);
    }

    // Mint badge
    let badge_count = BADGE_COUNT.load(deps.storage)?;
    let token_id = badge_count.to_string();

    let mint_msg = WasmMsg::Execute {
        contract_addr: config.nft_contract.to_string(),
        msg: to_json_binary(&Cw721ExecuteMsg::Mint {
            token_id: token_id.clone(),
            owner: pending.sender.to_string(),
            token_uri: None,
            extension: None,
        })?,
        funds: vec![],
    };

    BADGE_COUNT.save(deps.storage, &(badge_count + 1))?;
    PENDING_PROOF.remove(deps.storage);

    Ok(Response::new()
        .add_message(mint_msg)
        .add_attribute("action", "mint_badge")
        .add_attribute("recipient", pending.sender)
        .add_attribute("token_id", token_id)
        .add_attribute("suspect", verification.suspect))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => {
            let config = CONFIG.load(deps.storage)?;
            to_json_binary(&ConfigResponse {
                admin: config.admin.to_string(),
                nft_contract: config.nft_contract.to_string(),
                attestation_contract: config.attestation_contract.to_string(),
            })
        }
        QueryMsg::GetBadgeCount {} => {
            let count = BADGE_COUNT.load(deps.storage)?;
            to_json_binary(&BadgeCountResponse { count })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{message_info, mock_env, MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, ContractResult, OwnedDeps, SystemError, SystemResult,
        WasmQuery,
    };

    fn mock_dependencies() -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
        OwnedDeps {
            storage: MockStorage::default(),
            api: MockApi::default().with_prefix("xion"),
            querier: MockQuerier::default(),
            custom_query_type: std::marker::PhantomData,
        }
    }

    fn setup_instantiate(
        deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) -> (String, String, String) {
        let admin = deps.api.addr_make("admin").to_string();
        let nft = deps.api.addr_make("nft_contract").to_string();
        let attestation = deps.api.addr_make("attestation_contract").to_string();
        let info = message_info(&deps.api.addr_make("admin"), &[]);
        let msg = InstantiateMsg {
            admin: admin.clone(),
            nft_contract: nft.clone(),
            attestation_contract: attestation.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        (admin, nft, attestation)
    }

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let (admin, nft, attestation) = setup_instantiate(&mut deps);

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.admin.to_string(), admin);
        assert_eq!(config.nft_contract.to_string(), nft);
        assert_eq!(config.attestation_contract.to_string(), attestation);

        let count = BADGE_COUNT.load(deps.as_ref().storage).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_update_config_admin_only() {
        let mut deps = mock_dependencies();
        let (_, _, _) = setup_instantiate(&mut deps);

        // Non-admin should fail
        let non_admin = deps.api.addr_make("non_admin");
        let info = message_info(&non_admin, &[]);
        let msg = ExecuteMsg::UpdateConfig {
            admin: None,
            nft_contract: None,
            attestation_contract: None,
        };
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized);

        // Admin should succeed
        let admin = deps.api.addr_make("admin");
        let new_nft = deps.api.addr_make("new_nft").to_string();
        let info = message_info(&admin, &[]);
        let msg = ExecuteMsg::UpdateConfig {
            admin: None,
            nft_contract: Some(new_nft.clone()),
            attestation_contract: None,
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(res.attributes[0].value, "update_config");

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.nft_contract.to_string(), new_nft);
    }

    #[test]
    fn test_query_config() {
        let mut deps = mock_dependencies();
        let (admin, nft, attestation) = setup_instantiate(&mut deps);

        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetConfig {}).unwrap();
        let config: ConfigResponse = from_json(res).unwrap();
        assert_eq!(config.admin, admin);
        assert_eq!(config.nft_contract, nft);
        assert_eq!(config.attestation_contract, attestation);
    }

    #[test]
    fn test_query_badge_count() {
        let mut deps = mock_dependencies();
        setup_instantiate(&mut deps);

        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetBadgeCount {}).unwrap();
        let badge: BadgeCountResponse = from_json(res).unwrap();
        assert_eq!(badge.count, 0);
    }

    #[test]
    fn test_submit_proof_stores_pending() {
        let mut deps = mock_dependencies();
        let (_, _, _) = setup_instantiate(&mut deps);

        let user = deps.api.addr_make("user");
        let info = message_info(&user, &[]);
        let body = Binary::from(b"test body".to_vec());
        let msg = ExecuteMsg::SubmitProof {
            quote: Binary::from(vec![0u8; 100]),
            collateral: Binary::from(vec![0u8; 50]),
            event_log: vec![],
            response_body: body.clone(),
        };

        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Should have a submessage
        assert_eq!(res.messages.len(), 1);
        assert_eq!(res.messages[0].id, VERIFY_REPLY_ID);

        // Should have stored pending proof
        let pending = PENDING_PROOF.load(deps.as_ref().storage).unwrap();
        assert_eq!(pending.sender, user);
        assert_eq!(pending.response_body, body);
    }

    #[test]
    fn test_verification_result_parsing() {
        let json = r#"{"address":"xion1user","clean":true,"message_count":5,"suspect":"bad_actor","timestamp":1234}"#;
        let result: VerificationResult = from_json(json.as_bytes()).unwrap();
        assert!(result.clean);
        assert_eq!(result.address, "xion1user");
        assert_eq!(result.suspect, "bad_actor");
        assert_eq!(result.timestamp, 1234);
        assert_eq!(result.message_count, 5);
    }

    #[test]
    fn test_verification_result_not_clean() {
        let json = r#"{"address":"xion1user","clean":false,"message_count":5,"suspect":"bad","timestamp":1234}"#;
        let result: VerificationResult = from_json(json.as_bytes()).unwrap();
        assert!(!result.clean);
    }

    #[allow(deprecated)]
    #[test]
    fn test_reply_no_pending_proof() {
        let mut deps = mock_dependencies();
        setup_instantiate(&mut deps);

        let reply_msg = Reply {
            id: VERIFY_REPLY_ID,
            payload: Binary::default(),
            gas_used: 0,
            result: cosmwasm_std::SubMsgResult::Ok(cosmwasm_std::SubMsgResponse {
                events: vec![],
                msg_responses: vec![],
                data: None,
            }),
        };

        let err = reply(deps.as_mut(), mock_env(), reply_msg).unwrap_err();
        assert_eq!(err, ContractError::NoPendingProof);
    }

    fn mock_dependencies_with_queries(
        nft_contract: String,
        attestation_contract: String,
        record: VerificationRecord,
        owner_has_tokens: bool,
    ) -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
        let mut deps = mock_dependencies();

        deps.querier.update_wasm(move |query| match query {
            WasmQuery::Smart { contract_addr, msg: _ } => {
                if *contract_addr == attestation_contract {
                    SystemResult::Ok(ContractResult::Ok(
                        to_json_binary(&record).unwrap(),
                    ))
                } else if *contract_addr == nft_contract {
                    let tokens = if owner_has_tokens {
                        vec!["0".to_string()]
                    } else {
                        vec![]
                    };
                    SystemResult::Ok(ContractResult::Ok(
                        to_json_binary(&TokensResponse { tokens }).unwrap(),
                    ))
                } else {
                    SystemResult::Err(SystemError::NoSuchContract {
                        addr: contract_addr.clone(),
                    })
                }
            }
            _ => SystemResult::Err(SystemError::UnsupportedRequest {
                kind: "unsupported".to_string(),
            }),
        });

        deps
    }

    fn make_verification_result(sender: &str, clean: bool, timestamp: u64) -> Vec<u8> {
        let result = VerificationResult {
            address: sender.to_string(),
            clean,
            message_count: 1,
            suspect: "test_suspect".to_string(),
            timestamp,
        };
        serde_json::to_vec(&result).unwrap()
    }

    fn make_record(response_body: &[u8], all_passed: bool) -> VerificationRecord {
        let hash = hex::encode(Sha256::digest(response_body));
        VerificationRecord {
            quote_verified: true,
            rtmr3_verified: true,
            measurements_verified: true,
            events_verified: true,
            all_passed,
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec![],
            mr_td: "".to_string(),
            rtmr0: "".to_string(),
            rtmr1: "".to_string(),
            rtmr2: "".to_string(),
            rtmr3: "".to_string(),
            report_data: "".to_string(),
            response_body_verified: true,
            response_body_hash: Some(hash),
            mismatches: vec![],
            verifier: Addr::unchecked("verifier"),
            block_height: 100,
            block_time: 1000,
        }
    }

    #[allow(deprecated)]
    fn make_reply_with_quote_hash(quote_hash: &str) -> Reply {
        Reply {
            id: VERIFY_REPLY_ID,
            payload: Binary::default(),
            gas_used: 0,
            result: cosmwasm_std::SubMsgResult::Ok(cosmwasm_std::SubMsgResponse {
                events: vec![Event::new("wasm").add_attribute("quote_hash", quote_hash)],
                msg_responses: vec![],
                data: None,
            }),
        }
    }

    #[test]
    fn test_reply_attestation_not_passed() {
        let api = MockApi::default().with_prefix("xion");
        let nft = api.addr_make("nft_contract").to_string();
        let attestation = api.addr_make("attestation_contract").to_string();
        let sender = api.addr_make("user");

        let body = make_verification_result(&sender.to_string(), true, 1000);
        let mut record = make_record(&body, false);
        record.all_passed = false;
        record.mismatches = vec!["rtmr3".to_string()];

        let mut deps = mock_dependencies_with_queries(
            nft.clone(),
            attestation.clone(),
            record,
            false,
        );

        let info = message_info(&api.addr_make("admin"), &[]);
        let msg = InstantiateMsg {
            admin: api.addr_make("admin").to_string(),
            nft_contract: nft,
            attestation_contract: attestation,
        };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        PENDING_PROOF
            .save(
                deps.as_mut().storage,
                &PendingProof {
                    sender,
                    response_body: Binary::from(body),
                },
            )
            .unwrap();

        let reply_msg = make_reply_with_quote_hash("abc123");
        let err = reply(deps.as_mut(), mock_env(), reply_msg).unwrap_err();
        match err {
            ContractError::AttestationFailed(_) => {}
            _ => panic!("expected AttestationFailed, got: {:?}", err),
        }
    }

    #[test]
    fn test_reply_not_clean() {
        let api = MockApi::default().with_prefix("xion");
        let nft = api.addr_make("nft_contract").to_string();
        let attestation = api.addr_make("attestation_contract").to_string();
        let sender = api.addr_make("user");

        let body = make_verification_result(&sender.to_string(), false, 1000);
        let record = make_record(&body, true);

        let mut deps = mock_dependencies_with_queries(
            nft.clone(),
            attestation.clone(),
            record,
            false,
        );

        let info = message_info(&api.addr_make("admin"), &[]);
        let msg = InstantiateMsg {
            admin: api.addr_make("admin").to_string(),
            nft_contract: nft,
            attestation_contract: attestation,
        };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        PENDING_PROOF
            .save(
                deps.as_mut().storage,
                &PendingProof {
                    sender,
                    response_body: Binary::from(body),
                },
            )
            .unwrap();

        let reply_msg = make_reply_with_quote_hash("abc123");
        let err = reply(deps.as_mut(), mock_env(), reply_msg).unwrap_err();
        assert_eq!(err, ContractError::NotClean);
    }

    #[test]
    fn test_reply_address_mismatch() {
        let api = MockApi::default().with_prefix("xion");
        let nft = api.addr_make("nft_contract").to_string();
        let attestation = api.addr_make("attestation_contract").to_string();
        let sender = api.addr_make("user");

        // Body says "wrong_address" but sender is "user"
        let body = make_verification_result("wrong_address", true, 1000);
        let record = make_record(&body, true);

        let mut deps = mock_dependencies_with_queries(
            nft.clone(),
            attestation.clone(),
            record,
            false,
        );

        let info = message_info(&api.addr_make("admin"), &[]);
        let msg = InstantiateMsg {
            admin: api.addr_make("admin").to_string(),
            nft_contract: nft,
            attestation_contract: attestation,
        };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        PENDING_PROOF
            .save(
                deps.as_mut().storage,
                &PendingProof {
                    sender,
                    response_body: Binary::from(body),
                },
            )
            .unwrap();

        let reply_msg = make_reply_with_quote_hash("abc123");
        let err = reply(deps.as_mut(), mock_env(), reply_msg).unwrap_err();
        assert_eq!(err, ContractError::AddressMismatch);
    }

    #[test]
    fn test_reply_quote_too_old() {
        let api = MockApi::default().with_prefix("xion");
        let nft = api.addr_make("nft_contract").to_string();
        let attestation = api.addr_make("attestation_contract").to_string();
        let sender = api.addr_make("user");

        // timestamp is 0, block time will be ~1571797419 (mock_env default)
        let body = make_verification_result(&sender.to_string(), true, 0);
        let record = make_record(&body, true);

        let mut deps = mock_dependencies_with_queries(
            nft.clone(),
            attestation.clone(),
            record,
            false,
        );

        let info = message_info(&api.addr_make("admin"), &[]);
        let msg = InstantiateMsg {
            admin: api.addr_make("admin").to_string(),
            nft_contract: nft,
            attestation_contract: attestation,
        };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        PENDING_PROOF
            .save(
                deps.as_mut().storage,
                &PendingProof {
                    sender,
                    response_body: Binary::from(body),
                },
            )
            .unwrap();

        let reply_msg = make_reply_with_quote_hash("abc123");
        let err = reply(deps.as_mut(), mock_env(), reply_msg).unwrap_err();
        match err {
            ContractError::QuoteTooOld(_) => {}
            _ => panic!("expected QuoteTooOld, got: {:?}", err),
        }
    }

    #[test]
    fn test_reply_already_has_badge() {
        let api = MockApi::default().with_prefix("xion");
        let nft = api.addr_make("nft_contract").to_string();
        let attestation = api.addr_make("attestation_contract").to_string();
        let sender = api.addr_make("user");

        let env = mock_env();
        let block_time = env.block.time.seconds();
        let body = make_verification_result(&sender.to_string(), true, block_time);
        let record = make_record(&body, true);

        let mut deps = mock_dependencies_with_queries(
            nft.clone(),
            attestation.clone(),
            record,
            true, // user already has tokens
        );

        let info = message_info(&api.addr_make("admin"), &[]);
        let msg = InstantiateMsg {
            admin: api.addr_make("admin").to_string(),
            nft_contract: nft,
            attestation_contract: attestation,
        };
        instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

        PENDING_PROOF
            .save(
                deps.as_mut().storage,
                &PendingProof {
                    sender,
                    response_body: Binary::from(body),
                },
            )
            .unwrap();

        let reply_msg = make_reply_with_quote_hash("abc123");
        let err = reply(deps.as_mut(), env, reply_msg).unwrap_err();
        assert_eq!(err, ContractError::AlreadyHasBadge);
    }

    #[test]
    fn test_reply_success_mints_badge() {
        let api = MockApi::default().with_prefix("xion");
        let nft = api.addr_make("nft_contract").to_string();
        let attestation = api.addr_make("attestation_contract").to_string();
        let sender = api.addr_make("user");

        let env = mock_env();
        let block_time = env.block.time.seconds();
        let body = make_verification_result(&sender.to_string(), true, block_time);
        let record = make_record(&body, true);

        let mut deps = mock_dependencies_with_queries(
            nft.clone(),
            attestation.clone(),
            record,
            false,
        );

        let info = message_info(&api.addr_make("admin"), &[]);
        let msg = InstantiateMsg {
            admin: api.addr_make("admin").to_string(),
            nft_contract: nft,
            attestation_contract: attestation,
        };
        instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

        PENDING_PROOF
            .save(
                deps.as_mut().storage,
                &PendingProof {
                    sender: sender.clone(),
                    response_body: Binary::from(body),
                },
            )
            .unwrap();

        let reply_msg = make_reply_with_quote_hash("abc123");
        let res = reply(deps.as_mut(), env, reply_msg).unwrap();

        // Should have mint message
        assert_eq!(res.messages.len(), 1);

        // Badge count incremented
        let count = BADGE_COUNT.load(deps.as_ref().storage).unwrap();
        assert_eq!(count, 1);

        // Pending proof cleaned up
        assert!(PENDING_PROOF.may_load(deps.as_ref().storage).unwrap().is_none());

        // Check attributes
        assert_eq!(
            res.attributes,
            vec![
                cosmwasm_std::Attribute::new("action", "mint_badge"),
                cosmwasm_std::Attribute::new("recipient", sender.to_string()),
                cosmwasm_std::Attribute::new("token_id", "0"),
                cosmwasm_std::Attribute::new("suspect", "test_suspect"),
            ]
        );
    }
}
