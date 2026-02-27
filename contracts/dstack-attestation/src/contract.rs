use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use cw2::set_contract_version;

use crate::error::ContractResult;
use crate::execute;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{
    Config, ExpectedEvents, ExpectedMeasurements, CONFIG, EXPECTED_EVENTS, EXPECTED_MEASUREMENTS,
    VERIFICATIONS,
};
use crate::{CONTRACT_NAME, CONTRACT_VERSION};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> ContractResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = msg
        .admin
        .map(|a| deps.api.addr_validate(&a))
        .transpose()?
        .unwrap_or(info.sender);

    CONFIG.save(deps.storage, &Config { admin })?;

    if let Some(m) = msg.expected_measurements {
        EXPECTED_MEASUREMENTS.save(
            deps.storage,
            &ExpectedMeasurements {
                mr_td: m.mr_td,
                rtmr1: m.rtmr1,
                rtmr2: m.rtmr2,
                rtmr0: m.rtmr0,
                check_rtmr0: m.check_rtmr0,
            },
        )?;
    }

    if let Some(e) = msg.expected_events {
        EXPECTED_EVENTS.save(
            deps.storage,
            &ExpectedEvents {
                compose_hash: e.compose_hash,
                os_image_hash: e.os_image_hash,
            },
        )?;
    }

    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> ContractResult<Response> {
    match msg {
        ExecuteMsg::SetExpectedMeasurements(m) => {
            execute::set_expected_measurements(deps, info, m)
        }
        ExecuteMsg::SetExpectedEvents(e) => execute::set_expected_events(deps, info, e),
        ExecuteMsg::VerifyAttestation {
            quote,
            collateral,
            event_log,
            response_body,
        } => execute::verify_attestation(
            deps,
            env,
            info,
            quote.as_slice(),
            collateral.as_slice(),
            event_log,
            response_body.as_deref(),
        ),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_json_binary(&CONFIG.load(deps.storage)?),
        QueryMsg::GetExpectedMeasurements {} => {
            to_json_binary(&EXPECTED_MEASUREMENTS.load(deps.storage)?)
        }
        QueryMsg::GetExpectedEvents {} => to_json_binary(&EXPECTED_EVENTS.load(deps.storage)?),
        QueryMsg::GetVerification { quote_hash } => {
            to_json_binary(&VERIFICATIONS.load(deps.storage, &quote_hash)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{ExpectedEventsMsg, ExpectedMeasurementsMsg};
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{from_json, Addr};

    #[test]
    fn test_instantiate_default_admin() {
        let mut deps = mock_dependencies();
        let info = message_info(&Addr::unchecked("creator"), &[]);
        let msg = InstantiateMsg {
            admin: None,
            expected_measurements: None,
            expected_events: None,
        };

        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(res.attributes[0].value, "instantiate");

        let config: Config =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::GetConfig {}).unwrap()).unwrap();
        assert_eq!(config.admin.as_str(), "creator");
    }

    #[test]
    fn test_instantiate_with_measurements() {
        let mut deps = mock_dependencies();
        let info = message_info(&Addr::unchecked("creator"), &[]);
        let msg = InstantiateMsg {
            admin: None,
            expected_measurements: Some(ExpectedMeasurementsMsg {
                mr_td: "abcd".to_string(),
                rtmr1: "1111".to_string(),
                rtmr2: "2222".to_string(),
                rtmr0: None,
                check_rtmr0: false,
            }),
            expected_events: None,
        };

        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let m: ExpectedMeasurements = from_json(
            query(deps.as_ref(), mock_env(), QueryMsg::GetExpectedMeasurements {}).unwrap(),
        )
        .unwrap();
        assert_eq!(m.mr_td, "abcd");
        assert_eq!(m.rtmr1, "1111");
        assert_eq!(m.rtmr2, "2222");
        assert!(!m.check_rtmr0);
    }

    #[test]
    fn test_instantiate_with_events() {
        let mut deps = mock_dependencies();
        let info = message_info(&Addr::unchecked("creator"), &[]);
        let msg = InstantiateMsg {
            admin: None,
            expected_measurements: None,
            expected_events: Some(ExpectedEventsMsg {
                compose_hash: Some("deadbeef".to_string()),
                os_image_hash: None,
            }),
        };

        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let e: ExpectedEvents = from_json(
            query(deps.as_ref(), mock_env(), QueryMsg::GetExpectedEvents {}).unwrap(),
        )
        .unwrap();
        assert_eq!(e.compose_hash, Some("deadbeef".to_string()));
        assert_eq!(e.os_image_hash, None);
    }

    #[test]
    fn test_set_expected_measurements_admin_only() {
        let mut deps = mock_dependencies();
        let info = message_info(&Addr::unchecked("admin"), &[]);
        instantiate(
            deps.as_mut(),
            mock_env(),
            info,
            InstantiateMsg {
                admin: None,
                expected_measurements: None,
                expected_events: None,
            },
        )
        .unwrap();

        // Non-admin fails
        let bad_info = message_info(&Addr::unchecked("attacker"), &[]);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            bad_info,
            ExecuteMsg::SetExpectedMeasurements(ExpectedMeasurementsMsg {
                mr_td: "x".to_string(),
                rtmr1: "y".to_string(),
                rtmr2: "z".to_string(),
                rtmr0: None,
                check_rtmr0: false,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, crate::error::ContractError::Unauthorized));

        // Admin succeeds
        let good_info = message_info(&Addr::unchecked("admin"), &[]);
        execute(
            deps.as_mut(),
            mock_env(),
            good_info,
            ExecuteMsg::SetExpectedMeasurements(ExpectedMeasurementsMsg {
                mr_td: "beef".to_string(),
                rtmr1: "1111".to_string(),
                rtmr2: "2222".to_string(),
                rtmr0: None,
                check_rtmr0: false,
            }),
        )
        .unwrap();

        let m: ExpectedMeasurements = from_json(
            query(deps.as_ref(), mock_env(), QueryMsg::GetExpectedMeasurements {}).unwrap(),
        )
        .unwrap();
        assert_eq!(m.mr_td, "beef");
    }

    #[test]
    fn test_set_expected_events_admin_only() {
        let mut deps = mock_dependencies();
        let info = message_info(&Addr::unchecked("admin"), &[]);
        instantiate(
            deps.as_mut(),
            mock_env(),
            info,
            InstantiateMsg {
                admin: None,
                expected_measurements: None,
                expected_events: None,
            },
        )
        .unwrap();

        // Non-admin fails
        let bad_info = message_info(&Addr::unchecked("attacker"), &[]);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            bad_info,
            ExecuteMsg::SetExpectedEvents(ExpectedEventsMsg {
                compose_hash: Some("abc".to_string()),
                os_image_hash: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, crate::error::ContractError::Unauthorized));

        // Admin succeeds
        let good_info = message_info(&Addr::unchecked("admin"), &[]);
        execute(
            deps.as_mut(),
            mock_env(),
            good_info,
            ExecuteMsg::SetExpectedEvents(ExpectedEventsMsg {
                compose_hash: Some("cafe".to_string()),
                os_image_hash: Some("babe".to_string()),
            }),
        )
        .unwrap();

        let e: ExpectedEvents = from_json(
            query(deps.as_ref(), mock_env(), QueryMsg::GetExpectedEvents {}).unwrap(),
        )
        .unwrap();
        assert_eq!(e.compose_hash, Some("cafe".to_string()));
        assert_eq!(e.os_image_hash, Some("babe".to_string()));
    }
}
