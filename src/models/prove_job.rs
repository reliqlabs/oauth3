use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::prove_jobs)]
pub struct ProveJob {
    pub id: String,
    pub status: String,
    pub request_uri: String,
    pub response_body: Vec<u8>,
    pub quote_hex: Option<String>,
    pub proof_json: Option<String>,
    pub error_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub prover_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProverType {
    Sp1Cpu,
    Sp1Gpu,
    Sp1Network,
    GnarkCpu,
    GnarkGpu,
    GnarkGpuSync,
}

impl ProverType {
    /// Parse from `?prove=` query param value. Returns None if value doesn't request proving.
    pub fn from_query_value(value: &str) -> Option<Self> {
        match value {
            "true" | "1" => {
                let default = std::env::var("DEFAULT_PROVER").unwrap_or_else(|_| "sp1-cpu".into());
                Self::from_db(&default).or(Some(Self::Sp1Cpu))
            }
            "sp1" | "sp1-cpu" => Some(Self::Sp1Cpu),
            "sp1-gpu" => Some(Self::Sp1Gpu),
            "sp1-network" => Some(Self::Sp1Network),
            "gnark" | "gnark-cpu" => Some(Self::GnarkCpu),
            "gnark-gpu" => Some(Self::GnarkGpu),
            "gnark-gpu-sync" => Some(Self::GnarkGpuSync),
            _ => None,
        }
    }

    /// String representation for DB storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sp1Cpu => "sp1-cpu",
            Self::Sp1Gpu => "sp1-gpu",
            Self::Sp1Network => "sp1-network",
            Self::GnarkCpu => "gnark-cpu",
            Self::GnarkGpu => "gnark-gpu",
            Self::GnarkGpuSync => "gnark-gpu-sync",
        }
    }

    /// Returns true if this prover type should be handled synchronously (inline response).
    pub fn is_sync(&self) -> bool {
        matches!(self, Self::GnarkGpuSync)
    }

    /// Parse from DB string.
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "sp1-cpu" => Some(Self::Sp1Cpu),
            "sp1-gpu" => Some(Self::Sp1Gpu),
            "sp1-network" => Some(Self::Sp1Network),
            "gnark-cpu" => Some(Self::GnarkCpu),
            "gnark-gpu" => Some(Self::GnarkGpu),
            "gnark-gpu-sync" => Some(Self::GnarkGpuSync),
            _ => None,
        }
    }
}
