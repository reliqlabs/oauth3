use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("unauthorized")]
    Unauthorized,

    #[error("verification failed: {reason}")]
    VerificationFailed { reason: String },

    #[error("invalid collateral: {reason}")]
    InvalidCollateral { reason: String },

    #[error("quote already verified")]
    AlreadyVerified,

    #[error("not a TDX quote")]
    NotTdxQuote,
}

pub type ContractResult<T> = Result<T, ContractError>;
