use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Failed to decode base64 quote: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Failed to parse TDX quote: {0}")]
    QuoteParse(String),

    #[error("Report data mismatch: expected {expected}, got {actual}")]
    ReportDataMismatch { expected: String, actual: String },

    #[error("Invalid info response: {0}")]
    InvalidInfo(#[from] serde_json::Error),

    #[error("Quote verification failed: {0}")]
    QuoteVerification(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub quote: String,
    #[serde(rename = "eventLog", skip_serializing_if = "Option::is_none")]
    pub event_log: Option<String>,
    #[serde(rename = "vmConfig", skip_serializing_if = "Option::is_none")]
    pub vm_config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoResponse {
    pub version: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_info: Option<String>,
}

pub struct AttestationVerifier;

impl AttestationVerifier {
    pub fn new() -> Self {
        Self
    }

    /// Verify that the attestation quote matches the application info
    ///
    /// This verifies:
    /// 1. The quote can be parsed as a valid TDX quote
    /// 2. The reportData in the quote matches the hash of the info response
    pub fn verify_attestation(
        &self,
        attestation: &AttestationResponse,
        info: &InfoResponse,
    ) -> Result<VerificationReport, VerificationError> {
        // Parse the base64-encoded quote
        let quote_bytes = base64::engine::general_purpose::STANDARD
            .decode(&attestation.quote)?;

        // Parse TDX quote to extract reportData
        let quote = tdx_quote::Quote::from_bytes(&quote_bytes)
            .map_err(|e| VerificationError::QuoteParse(e.to_string()))?;

        // Get report data from quote (64 bytes of report data)
        let report_data = quote.report_input_data();

        // Calculate expected report data from info
        let info_json = serde_json::to_vec(info)?;
        let expected_report_data = self.calculate_report_data(&info_json);

        // Verify report data matches
        if &expected_report_data[..] != report_data {
            return Err(VerificationError::ReportDataMismatch {
                expected: hex::encode(expected_report_data),
                actual: hex::encode(report_data),
            });
        }

        Ok(VerificationReport {
            quote_valid: true,
            report_data_valid: true,
            info: info.clone(),
        })
    }

    /// Calculate report data from input bytes
    ///
    /// Matches the logic in DstackClient::get_quote:
    /// - If data > 64 bytes: SHA256 hash
    /// - If data <= 64 bytes: zero-pad to 64 bytes
    fn calculate_report_data(&self, data: &[u8]) -> Vec<u8> {
        if data.len() > 64 {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        } else {
            let mut padded = vec![0u8; 64];
            padded[..data.len()].copy_from_slice(data);
            padded
        }
    }
}

impl Default for AttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    pub quote_valid: bool,
    pub report_data_valid: bool,
    pub info: InfoResponse,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_report_data_short() {
        let verifier = AttestationVerifier::new();
        let data = b"hello";
        let result = verifier.calculate_report_data(data);

        assert_eq!(result.len(), 64);
        assert_eq!(&result[..5], b"hello");
        assert_eq!(&result[5..], &vec![0u8; 59][..]);
    }

    #[test]
    fn test_calculate_report_data_long() {
        let verifier = AttestationVerifier::new();
        let data = vec![0u8; 100];
        let result = verifier.calculate_report_data(&data);

        assert_eq!(result.len(), 32); // SHA256 output
    }
}
