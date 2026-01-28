//! Scan models

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateScanRequest {
    pub name: String,
    pub claims: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanStatus {
    pub id: Uuid,
    pub status: String,
    pub progress: f32,
    pub message: Option<String>,
}
