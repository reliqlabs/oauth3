//! Embedded TDX attestation verifier
//!
//! This is a lightweight library for TDX quote verification, based on the
//! official dstack-verifier v0.5.5 verification logic.

use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
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

    #[error("TCB status not UpToDate: {0}")]
    TcbStatusNotCurrent(String),

    #[error("RTMR mismatch at index {index}: expected {expected}, got {actual}")]
    RtmrMismatch {
        index: usize,
        expected: String,
        actual: String,
    },

    #[error("Event log verification failed: {0}")]
    EventLogVerification(String),

    #[error("Collateral fetch failed: {0}")]
    CollateralFetch(String),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

/// Attestation response from dstack GetQuote endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// Base64-encoded TDX quote
    pub quote: String,
    /// JSON-encoded event log (optional)
    #[serde(rename = "eventLog", skip_serializing_if = "Option::is_none")]
    pub event_log: Option<String>,
    /// JSON-encoded VM config (optional)
    #[serde(rename = "vmConfig", skip_serializing_if = "Option::is_none")]
    pub vm_config: Option<String>,
}

/// Configuration for the verifier
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// PCCS URL for quote verification (default: https://pccs.phala.network)
    pub pccs_url: String,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            pccs_url: "https://pccs.phala.network".to_string(),
        }
    }
}

/// TDX attestation verifier
pub struct AttestationVerifier {
    config: VerifierConfig,
}

impl AttestationVerifier {
    pub fn new() -> Self {
        Self {
            config: VerifierConfig::default(),
        }
    }

    pub fn with_config(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Verify attestation quote
    ///
    /// This performs:
    /// 1. Full TDX quote verification using dcap-qvl (TCB status, certificates, collateral)
    /// 2. Event log RTMR replay verification (if event log provided)
    /// 3. Report data extraction
    pub async fn verify_attestation(
        &self,
        attestation: &AttestationResponse,
    ) -> Result<VerificationReport, VerificationError> {
        // Parse the base64-encoded quote
        let quote_bytes = base64::engine::general_purpose::STANDARD
            .decode(&attestation.quote)?;

        // Parse the quote to extract reportData and RTMRs
        let parsed_quote = dcap_qvl::quote::Quote::parse(&quote_bytes)
            .map_err(|e: anyhow::Error| {
                VerificationError::QuoteParse(format!("Failed to parse quote: {}", e))
            })?;

        // Get collateral from PCCS
        let collateral = dcap_qvl::collateral::get_collateral(&self.config.pccs_url, &quote_bytes[..])
            .await
            .map_err(|e| VerificationError::CollateralFetch(format!("Collateral fetch failed: {}", e)))?;

        // Verify quote with dcap-qvl
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let verified = dcap_qvl::verify::verify(&quote_bytes, &collateral, now)
            .map_err(|e: anyhow::Error| VerificationError::QuoteVerification(e.to_string()))?;

        // Extract TCB status and advisory IDs
        let tcb_status = verified.status.clone();
        let advisory_ids = verified.advisory_ids.clone();

        // Extract TDReport10 from the parsed quote
        let td_report = parsed_quote.report.as_td10()
            .ok_or_else(|| VerificationError::QuoteParse("Quote is not a TDX quote".to_string()))?;

        // Extract report data
        let report_data = hex::encode(&td_report.report_data);

        // Extract RTMRs
        let rtmrs = RTMRs {
            mrtd: hex::encode(&td_report.mr_td),
            rtmr0: hex::encode(&td_report.rt_mr0),
            rtmr1: hex::encode(&td_report.rt_mr1),
            rtmr2: hex::encode(&td_report.rt_mr2),
            rtmr3: hex::encode(&td_report.rt_mr3),
        };

        // Verify event log if provided
        let event_log_verified = if let Some(event_log_json) = &attestation.event_log {
            let event_log: Vec<LogEntry> = serde_json::from_str(event_log_json)?;
            if !event_log.is_empty() {
                let quote_rtmrs = [
                    &td_report.rt_mr0[..],
                    &td_report.rt_mr1[..],
                    &td_report.rt_mr2[..],
                    &td_report.rt_mr3[..],
                ];
                self.verify_event_log(&event_log, &quote_rtmrs)?;
                true
            } else {
                false // Empty event log
            }
        } else {
            false // No event log provided
        };

        Ok(VerificationReport {
            quote_verified: true,
            event_log_verified,
            tcb_status,
            advisory_ids,
            report_data,
            rtmrs,
        })
    }

    /// Verify event log by replaying RTMR calculations
    ///
    /// Uses SHA-384 hash chain starting from init value (48 zero bytes)
    fn verify_event_log(
        &self,
        event_log: &[LogEntry],
        quote_rtmrs: &[&[u8]; 4],
    ) -> Result<(), VerificationError> {
        // Initialize RTMRs (48 bytes each, all zeros)
        let mut rtmr: [Vec<u8>; 4] = [
            vec![0u8; 48],
            vec![0u8; 48],
            vec![0u8; 48],
            vec![0u8; 48],
        ];

        // Replay event log
        for entry in event_log {
            let imr_index = entry.imr as usize;
            if imr_index >= 4 {
                return Err(VerificationError::EventLogVerification(format!(
                    "Invalid RTMR index: {}",
                    imr_index
                )));
            }

            // Decode the digest from hex
            let digest = hex::decode(&entry.digest)?;

            // Validate digest against event payload
            entry.validate()
                .map_err(|e| VerificationError::EventLogVerification(format!("Event validation failed: {}", e)))?;

            // Update RTMR: SHA384(current_rtmr || digest)
            let mut hasher = Sha384::new();
            hasher.update(&rtmr[imr_index]);
            hasher.update(&digest);
            rtmr[imr_index] = hasher.finalize().to_vec();
        }

        // Compare calculated RTMRs with quote RTMRs
        for i in 0..4 {
            if rtmr[i] != quote_rtmrs[i] {
                return Err(VerificationError::RtmrMismatch {
                    index: i,
                    expected: hex::encode(quote_rtmrs[i]),
                    actual: hex::encode(&rtmr[i]),
                });
            }
        }

        Ok(())
    }
}

impl Default for AttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub quote_verified: bool,
    pub event_log_verified: bool,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
    pub report_data: String,
    pub rtmrs: RTMRs,
}

/// Runtime measurements from TDX quote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RTMRs {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
}

/// Event log entry from dstack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// RTMR index (0-3)
    pub imr: u32,
    /// Event type code
    pub event_type: u32,
    /// Hex-encoded digest
    pub digest: String,
    /// Event name
    pub event: String,
    /// Event-specific payload (hex-encoded)
    pub event_payload: String,
}

impl LogEntry {
    /// Validate that digest matches SHA384(event_payload)
    pub fn validate(&self) -> Result<()> {
        let payload_bytes = hex::decode(&self.event_payload)
            .context("Failed to decode event payload")?;

        let mut hasher = Sha384::new();
        hasher.update(&payload_bytes);
        let computed_digest = hasher.finalize();

        let digest_bytes = hex::decode(&self.digest)
            .context("Failed to decode digest")?;

        if computed_digest[..] != digest_bytes[..] {
            anyhow::bail!(
                "Digest mismatch for event '{}': expected {}, got {}",
                self.event,
                hex::encode(&digest_bytes),
                hex::encode(&computed_digest)
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[tokio::test]
    async fn test_verify_attestation_with_real_quote() {
        // TODO: Fill in with real attestation data from Phala deployment
        let hex_quote = "040002008100000000000000939a7233f79c4ca9940a0db3957f0607228b1b2533416561505b6d6ef4236c79000000000b0105000000000000000000000000007bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000702000000000000f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077013861589216745f0eb8f4fcb8b19463ca8e0d46ca5a980360c73379cf2c95f875000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027b610ab0555482f8a3868524093bdf3cdbe2539f81dfeeb886864654cb2fe3422f7fc36d4bab6fa46683aad11d1ba7daa9380dc33b14728a9adb222437cf14db2d40ffc4d7061d8f3c329f6c6b339f71486d33521287e8faeae22301f4d8151bdc76d9cbe95bd6e977969bc3e2c5afab2e85cb6b19dc17cc71cefe27cfe7b4fe29605f275cba379ff8980caaeee6749247265e1d532be641d2d421019c7b8da7cdaaada9e27ab7de3a82a078199c408650a862489a60783f3b5b6b5a00373000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d0100000bf3b542abe9c6a17e70b1e4d9c98186d366bd47be6d5a52a3f967406b854264f6c0413c2f532b126cb20d9cfe63ebb484d9ddeb5ef0b5aba07fd41a88fcfec28d4aea0ab2a5cfdc479e2b02599d8e30d7dcbcc11bc550681a15d0777d298867465adda0877a31bf4a80dd227d0b1c53f263afe5136081698ff89101622c5616f06004a10000005050a0a05ff00020000000000000000000000000000000000000000000000000000000000000000000000000000000015000000000000000700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bbf5f2fdd1fd1fc2e16e13810b22d19ded102d47dcde36beb537b37730625faa000000000000000000000000000000000000000000000000000000000000000071c2750da5eaffeaee1b0580477c62384bc5e8aad447e0c7702215f44f80757acd7db9ead61e4a9dac2cb0524e623c8c81b6bea2f7b5abf4d39d9b38f8b042e52000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0500620e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494945386a4343424a69674177494241674956414e5a424d42727175543357555555623435426c4f637a33633669424d416f4743437147534d343942414d430a4d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d0a45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155450a4341774351304578437a414a42674e5642415954416c56544d423458445449314d5449794e5441324d6a4d784e566f5844544d794d5449794e5441324d6a4d780a4e566f77634445694d434147413155454177775a535735305a5777675530645949464244537942445a584a3061575a70593246305a5445614d426747413155450a43677752535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d517377435159440a5651514944414a445154454c4d416b474131554542684d4356564d775754415442676371686b6a4f5051494242676771686b6a4f50514d4242774e43414152390a463045517555582b43746677516a61726a6b4270436f4e646361746642503168444e2f776677397042797851584b42464c74696e6e6c58637a7856616948544c0a724f2f6352764f7437556375764d793231772f586f3449444454434341776b77487759445652306a42426777466f41556c5739647a62306234656c4153636e550a3944504f4156634c336c5177617759445652306642475177596a42676f46366758495a616148523063484d364c79396863476b7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253397a5a3367765932567964476c6d61574e6864476c76626939324e4339775932746a636d772f593245390a6347786864475a76636d306d5a57356a62325270626d63395a4756794d4230474131556444675157424252547a744d5341354376394c675467314c37433136540a4b5079553044414f42674e56485138424166384542414d434273417744415944565230544151482f4241497741444343416a6f4743537147534962345451454e0a41515343416973776767496e4d42344743697147534962345451454e415145454544347762684d376639716e75336e32646a544c556777776767466b42676f710a686b69472b453042445145434d4949425644415142677371686b69472b45304244514543415149424254415142677371686b69472b45304244514543416749420a4254415142677371686b69472b4530424451454341774942416a415142677371686b69472b4530424451454342414942416a415142677371686b69472b4530420a44514543425149424254415242677371686b69472b4530424451454342674943415038774541594c4b6f5a496876684e4151304241676343415141774541594c0a4b6f5a496876684e4151304241676743415149774541594c4b6f5a496876684e4151304241676b43415141774541594c4b6f5a496876684e4151304241676f430a415141774541594c4b6f5a496876684e4151304241677343415141774541594c4b6f5a496876684e4151304241677743415141774541594c4b6f5a496876684e0a4151304241673043415141774541594c4b6f5a496876684e4151304241673443415141774541594c4b6f5a496876684e4151304241673843415141774541594c0a4b6f5a496876684e4151304241684143415141774541594c4b6f5a496876684e4151304241684543415130774877594c4b6f5a496876684e41513042416849450a45415546416749462f7741434141414141414141414141774541594b4b6f5a496876684e4151304241775143414141774641594b4b6f5a496876684e415130420a42415147494b4276414141414d41384743697147534962345451454e4151554b415145774867594b4b6f5a496876684e4151304242675151704548632f65354d0a784b43445636306651747932666a424542676f71686b69472b453042445145484d4459774541594c4b6f5a496876684e4151304242774542416638774541594c0a4b6f5a496876684e4151304242774942416638774541594c4b6f5a496876684e4151304242774d4241663877436759494b6f5a497a6a304541774944534141770a5251496742523535766d573369362f4a716136642f6c3071326a44503877434f30393842327741684d6d336d38546343495144333042462f547a2b5a6f4c664b0a36676747754b4f58487145777a5232386144464c6245794a6e44594661413d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();

        let quote_bytes = hex::decode(&hex_quote).expect("Failed to decode hex quote");
        let quote_b64 = base64::engine::general_purpose::STANDARD.encode(&quote_bytes);
        let expected_report_data =
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let expected_mrtd =
            "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077";
        let expected_rtmr0 =
            "027b610ab0555482f8a3868524093bdf3cdbe2539f81dfeeb886864654cb2fe3422f7fc36d4bab6fa46683aad11d1ba7";
        let expected_rtmr1 =
            "daa9380dc33b14728a9adb222437cf14db2d40ffc4d7061d8f3c329f6c6b339f71486d33521287e8faeae22301f4d815";
        let expected_rtmr2 =
            "1bdc76d9cbe95bd6e977969bc3e2c5afab2e85cb6b19dc17cc71cefe27cfe7b4fe29605f275cba379ff8980caaeee674";
        let expected_rtmr3 =
            "9247265e1d532be641d2d421019c7b8da7cdaaada9e27ab7de3a82a078199c408650a862489a60783f3b5b6b5a003730";

        let attestation = AttestationResponse {
            quote: quote_b64,
            event_log: Some(r#"[]"#.to_string()),
            vm_config: None,
        };

        let verifier = AttestationVerifier::new();
        let result = verifier.verify_attestation(&attestation).await;

        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        let report = result.unwrap();
        assert_eq!(report.tcb_status, "UpToDate");
        assert!(report.quote_verified);
        assert_eq!(report.report_data, expected_report_data);
        assert_eq!(report.rtmrs.mrtd, expected_mrtd);
        assert_eq!(report.rtmrs.rtmr0, expected_rtmr0);
        assert_eq!(report.rtmrs.rtmr1, expected_rtmr1);
        assert_eq!(report.rtmrs.rtmr2, expected_rtmr2);
        assert_eq!(report.rtmrs.rtmr3, expected_rtmr3);
    }

    #[test]
    fn test_event_log_rtmr_replay() {
        let verifier = AttestationVerifier::new();

        // Sample event log with a single event
        let event_log = vec![
            LogEntry {
                imr: 0,
                event_type: 1,
                digest: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                event: "test-event".to_string(),
                event_payload: "test-payload".to_string(),
            }
        ];

        // Expected RTMR after one extend with all zeros
        let mut hasher = sha2::Sha384::new();
        hasher.update(&[0u8; 48]); // Initial RTMR
        hasher.update(&[0u8; 48]); // Digest padded to 48 bytes
        let expected_rtmr0 = hasher.finalize().to_vec();

        let quote_rtmrs = [
            &expected_rtmr0[..],
            &[0u8; 48][..],
            &[0u8; 48][..],
            &[0u8; 48][..],
        ];

        let result = verifier.verify_event_log(&event_log, &quote_rtmrs);
        assert!(result.is_ok(), "Event log verification failed: {:?}", result.err());
    }
}
