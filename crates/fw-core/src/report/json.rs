//! JSON report generation

use crate::{CoreResult, ScanResult};

pub fn generate(result: &ScanResult) -> CoreResult<String> {
    serde_json::to_string_pretty(result)
        .map_err(|e| crate::CoreError::Analysis(format!("JSON serialization failed: {}", e)))
}
