//! Report models

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportRequest {
    pub format: String,
}
