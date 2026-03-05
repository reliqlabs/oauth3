use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

// Used in #[returns(...)] attributes for QueryResponses derive
#[allow(unused_imports)]
use crate::state::{Config, ExpectedConfig, VerificationRecord};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: Option<String>,
    pub expected_config: Option<ExpectedConfigMsg>,
}

#[cw_serde]
pub struct ExpectedConfigMsg {
    pub mr_td: Option<String>,
    pub rt_mr0: Option<String>,
    pub rt_mr1: Option<String>,
    pub rt_mr2: Option<String>,
    pub rt_mr3: Option<String>,
    pub report_data: Option<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    SetExpectedConfig {
        mr_td: Option<String>,
        rt_mr0: Option<String>,
        rt_mr1: Option<String>,
        rt_mr2: Option<String>,
        rt_mr3: Option<String>,
        report_data: Option<String>,
    },
    VerifyQuote {
        quote: Binary,
        collateral: Binary,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Config)]
    GetConfig {},
    #[returns(ExpectedConfig)]
    GetExpectedConfig {},
    #[returns(VerificationRecord)]
    GetVerification { quote_hash: String },
}
