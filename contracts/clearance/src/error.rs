use cosmwasm_std::StdError;
use thiserror::Error;

// PartialEq derived only for non-Std variants (StdError doesn't impl PartialEq in v3).
// Tests use matches!() for Std variants.
#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("unauthorized")]
    Unauthorized,

    #[error("not clean")]
    NotClean,

    #[error("already has badge")]
    AlreadyHasBadge,

    #[error("invalid result format")]
    InvalidResultFormat,

    #[error("attestation failed: {0}")]
    AttestationFailed(String),

    #[error("quote too old: {0}")]
    QuoteTooOld(String),

    #[error("timestamp in future")]
    TimestampInFuture,

    #[error("address mismatch")]
    AddressMismatch,

    #[error("no pending proof")]
    NoPendingProof,

    #[error("response body mismatch")]
    ResponseBodyMismatch,
}

impl PartialEq for ContractError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Std(_), Self::Std(_)) => false, // not comparable
            (Self::Unauthorized, Self::Unauthorized) => true,
            (Self::NotClean, Self::NotClean) => true,
            (Self::AlreadyHasBadge, Self::AlreadyHasBadge) => true,
            (Self::InvalidResultFormat, Self::InvalidResultFormat) => true,
            (Self::AttestationFailed(a), Self::AttestationFailed(b)) => a == b,
            (Self::QuoteTooOld(a), Self::QuoteTooOld(b)) => a == b,
            (Self::TimestampInFuture, Self::TimestampInFuture) => true,
            (Self::AddressMismatch, Self::AddressMismatch) => true,
            (Self::NoPendingProof, Self::NoPendingProof) => true,
            (Self::ResponseBodyMismatch, Self::ResponseBodyMismatch) => true,
            _ => false,
        }
    }
}
