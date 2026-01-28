//! Evidence collection and preservation

pub mod collector;
pub mod export;

pub use collector::EvidenceCollector;

use crate::analysis::{AnalysisResult, CapabilityFinding};
use crate::claims::ClaimVerdict;
use crate::dormant::DormantCapability;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Evidence of a capability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub finding_id: String,
    pub file_path: String,
    pub byte_offset: u64,
    pub byte_length: usize,
    pub content_hash: String,
    pub matched_data: Vec<u8>,
    pub context_before: Vec<u8>,
    pub context_after: Vec<u8>,
    pub reproduction_notes: String,
}

impl Evidence {
    pub fn new(
        finding_id: &str,
        file_path: &str,
        offset: u64,
        data: &[u8],
        context_before: Vec<u8>,
        context_after: Vec<u8>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());

        Self {
            id: Uuid::new_v4(),
            finding_id: finding_id.to_string(),
            file_path: file_path.to_string(),
            byte_offset: offset,
            byte_length: data.len(),
            content_hash: hash,
            matched_data: data.to_vec(),
            context_before,
            context_after,
            reproduction_notes: format!("Evidence at offset 0x{:x} in {}", offset, file_path),
        }
    }

    /// Get matched data as string (lossy)
    pub fn as_string(&self) -> String {
        String::from_utf8_lossy(&self.matched_data).to_string()
    }

    /// Get hex dump of matched data
    pub fn hex_dump(&self) -> String {
        hex::encode(&self.matched_data)
    }

    /// Get full context (before + matched + after)
    pub fn full_context(&self) -> Vec<u8> {
        let mut ctx = self.context_before.clone();
        ctx.extend(&self.matched_data);
        ctx.extend(&self.context_after);
        ctx
    }
}

/// Evidence pack for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePack {
    pub scan_id: Uuid,
    pub artifact_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub evidence_items: Vec<Evidence>,
    pub total_count: usize,
}

impl EvidencePack {
    pub fn new(scan_id: Uuid, artifact_hash: &str, evidence: Vec<Evidence>) -> Self {
        let count = evidence.len();
        Self {
            scan_id,
            artifact_hash: artifact_hash.to_string(),
            timestamp: chrono::Utc::now(),
            evidence_items: evidence,
            total_count: count,
        }
    }

    /// Export to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
