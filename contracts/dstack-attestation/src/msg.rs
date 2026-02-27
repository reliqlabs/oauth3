use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

#[allow(unused_imports)]
use crate::state::{Config, ExpectedEvents, ExpectedMeasurements, VerificationRecord};

#[cw_serde]
pub struct ExpectedMeasurementsMsg {
    pub mr_td: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr0: Option<String>,
    pub check_rtmr0: bool,
}

#[cw_serde]
pub struct ExpectedEventsMsg {
    pub compose_hash: Option<String>,
    pub os_image_hash: Option<String>,
}

#[cw_serde]
pub struct EventLogEntry {
    pub event: String,
    pub payload: Binary,
}

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: Option<String>,
    pub expected_measurements: Option<ExpectedMeasurementsMsg>,
    pub expected_events: Option<ExpectedEventsMsg>,
}

#[cw_serde]
pub enum ExecuteMsg {
    SetExpectedMeasurements(ExpectedMeasurementsMsg),
    SetExpectedEvents(ExpectedEventsMsg),
    VerifyAttestation {
        quote: Binary,
        collateral: Binary,
        event_log: Vec<EventLogEntry>,
        /// Optional response body from the TEE's `?attest=true` middleware.
        /// If provided, SHA256(response_body) is checked against report_data[..32].
        response_body: Option<Binary>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Config)]
    GetConfig {},
    #[returns(ExpectedMeasurements)]
    GetExpectedMeasurements {},
    #[returns(ExpectedEvents)]
    GetExpectedEvents {},
    #[returns(VerificationRecord)]
    GetVerification { quote_hash: String },
}
