use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use cw2::set_contract_version;

use crate::error::ContractResult;
use crate::execute;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, ExpectedConfig, CONFIG, EXPECTED_CONFIG, VERIFICATIONS};
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

    if let Some(ec) = msg.expected_config {
        EXPECTED_CONFIG.save(
            deps.storage,
            &ExpectedConfig {
                mr_td: ec.mr_td,
                rt_mr0: ec.rt_mr0,
                rt_mr1: ec.rt_mr1,
                rt_mr2: ec.rt_mr2,
                rt_mr3: ec.rt_mr3,
                report_data: ec.report_data,
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
        ExecuteMsg::SetExpectedConfig {
            mr_td,
            rt_mr0,
            rt_mr1,
            rt_mr2,
            rt_mr3,
            report_data,
        } => execute::set_expected_config(deps, info, mr_td, rt_mr0, rt_mr1, rt_mr2, rt_mr3, report_data),
        ExecuteMsg::VerifyQuote { quote, collateral } => {
            execute::verify_quote(deps, env, info, quote.as_slice(), collateral.as_slice())
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_json_binary(&CONFIG.load(deps.storage)?),
        QueryMsg::GetExpectedConfig {} => {
            to_json_binary(&EXPECTED_CONFIG.load(deps.storage)?)
        }
        QueryMsg::GetVerification { quote_hash } => {
            to_json_binary(&VERIFICATIONS.load(deps.storage, &quote_hash)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, message_info};
    use cosmwasm_std::{from_json, Addr};
    use crate::msg::ExpectedConfigMsg;

    #[test]
    fn test_instantiate_default_admin() {
        let mut deps = mock_dependencies();
        let info = message_info(&Addr::unchecked("creator"), &[]);
        let msg = InstantiateMsg {
            admin: None,
            expected_config: None,
        };

        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(res.attributes[0].value, "instantiate");

        let config: Config = from_json(
            query(deps.as_ref(), mock_env(), QueryMsg::GetConfig {}).unwrap(),
        )
        .unwrap();
        assert_eq!(config.admin.as_str(), "creator");
    }

    #[test]
    fn test_instantiate_with_expected_config() {
        let mut deps = mock_dependencies();
        let info = message_info(&Addr::unchecked("creator"), &[]);
        let msg = InstantiateMsg {
            admin: None,
            expected_config: Some(ExpectedConfigMsg {
                mr_td: Some("abcd".to_string()),
                rt_mr0: None,
                rt_mr1: None,
                rt_mr2: None,
                rt_mr3: None,
                report_data: None,
            }),
        };

        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let ec: ExpectedConfig = from_json(
            query(deps.as_ref(), mock_env(), QueryMsg::GetExpectedConfig {}).unwrap(),
        )
        .unwrap();
        assert_eq!(ec.mr_td, Some("abcd".to_string()));
    }

    #[test]
    fn test_set_expected_config_admin_only() {
        let mut deps = mock_dependencies();
        let info = message_info(&Addr::unchecked("admin"), &[]);
        let msg = InstantiateMsg {
            admin: None,
            expected_config: None,
        };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Non-admin should fail
        let bad_info = message_info(&Addr::unchecked("attacker"), &[]);
        let exec_msg = ExecuteMsg::SetExpectedConfig {
            mr_td: Some("dead".to_string()),
            rt_mr0: None,
            rt_mr1: None,
            rt_mr2: None,
            rt_mr3: None,
            report_data: None,
        };
        let err = execute(deps.as_mut(), mock_env(), bad_info, exec_msg).unwrap_err();
        assert!(matches!(err, crate::error::ContractError::Unauthorized));

        // Admin should succeed
        let good_info = message_info(&Addr::unchecked("admin"), &[]);
        let exec_msg = ExecuteMsg::SetExpectedConfig {
            mr_td: Some("beef".to_string()),
            rt_mr0: None,
            rt_mr1: None,
            rt_mr2: None,
            rt_mr3: None,
            report_data: None,
        };
        execute(deps.as_mut(), mock_env(), good_info, exec_msg).unwrap();

        let ec: ExpectedConfig = from_json(
            query(deps.as_ref(), mock_env(), QueryMsg::GetExpectedConfig {}).unwrap(),
        )
        .unwrap();
        assert_eq!(ec.mr_td, Some("beef".to_string()));
    }
}
