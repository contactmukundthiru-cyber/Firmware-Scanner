//! Database schema types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub artifact_hash: Option<String>,
    pub artifact_size: i64,
    pub config: serde_json::Value,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub capability_type: String,
    pub severity: String,
    pub is_dormant: bool,
    pub evidence_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct ClaimVerdict {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub claim_type: String,
    pub compatible: String,
    pub failing_conditions: Option<serde_json::Value>,
    pub evidence_ids: Vec<Uuid>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub file_path: String,
    pub byte_offset: i64,
    pub byte_length: i64,
    pub content_hash: String,
    pub context_data: Option<Vec<u8>>,
    pub reproduction_script: Option<String>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Report {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub format: String,
    pub generated_at: DateTime<Utc>,
    pub file_path: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}
