//! Capability analysis engine
//!
//! Contains 6 core capability detectors:
//! - Networking
//! - Telemetry
//! - Storage
//! - Update/Remote Control
//! - Identity/Tracking
//! - Cryptography

pub mod crypto;
pub mod identity;
pub mod networking;
pub mod storage;
pub mod telemetry;
pub mod update;

use crate::evidence::Evidence;
use crate::ingestion::FirmwareArtifact;
use crate::{CoreError, CoreResult, Severity, TriState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use crypto::CryptoDetector;
pub use identity::IdentityDetector;
pub use networking::NetworkingDetector;
pub use storage::StorageDetector;
pub use telemetry::TelemetryDetector;
pub use update::UpdateDetector;

/// Configuration for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub min_string_length: usize,
    pub max_findings_per_category: usize,
    pub include_dormant: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            min_string_length: 4,
            max_findings_per_category: 1000,
            include_dormant: true,
        }
    }
}

/// Capability type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityType {
    Networking,
    Telemetry,
    Storage,
    Update,
    Identity,
    Crypto,
}

impl std::fmt::Display for CapabilityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapabilityType::Networking => write!(f, "Networking"),
            CapabilityType::Telemetry => write!(f, "Telemetry"),
            CapabilityType::Storage => write!(f, "Storage"),
            CapabilityType::Update => write!(f, "Update"),
            CapabilityType::Identity => write!(f, "Identity"),
            CapabilityType::Crypto => write!(f, "Crypto"),
        }
    }
}

/// Individual capability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityFinding {
    pub id: String,
    pub capability_type: CapabilityType,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f32,
    pub is_dormant: bool,
    pub evidence: Vec<Evidence>,
    pub tags: Vec<String>,
}

/// Result from a single detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorResult {
    pub capability_type: CapabilityType,
    pub capability_present: TriState,
    pub findings: Vec<CapabilityFinding>,
    pub evidence: Vec<Evidence>,
    pub summary: String,
}

impl DetectorResult {
    pub fn new(capability_type: CapabilityType) -> Self {
        Self {
            capability_type,
            capability_present: TriState::Indeterminate,
            findings: Vec::new(),
            evidence: Vec::new(),
            summary: String::new(),
        }
    }

    pub fn with_finding(mut self, finding: CapabilityFinding) -> Self {
        self.capability_present = TriState::Yes;
        self.findings.push(finding);
        self
    }

    pub fn set_present(&mut self, present: TriState) {
        self.capability_present = present;
    }

    pub fn add_finding(&mut self, finding: CapabilityFinding) {
        self.capability_present = TriState::Yes;
        self.findings.push(finding);
    }

    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
    }

    pub fn set_summary(&mut self, summary: String) {
        self.summary = summary;
    }
}

/// Combined analysis result from all detectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub capabilities: HashMap<CapabilityType, DetectorResult>,
    pub all_findings: Vec<CapabilityFinding>,
    pub total_evidence: Vec<Evidence>,
}

impl AnalysisResult {
    pub fn new() -> Self {
        Self {
            capabilities: HashMap::new(),
            all_findings: Vec::new(),
            total_evidence: Vec::new(),
        }
    }

    /// Merge multiple detector results
    pub fn merge(results: Vec<DetectorResult>) -> Self {
        let mut merged = Self::new();

        for result in results {
            merged.all_findings.extend(result.findings.clone());
            merged.total_evidence.extend(result.evidence.clone());
            merged.capabilities.insert(result.capability_type, result);
        }

        merged
    }

    /// Check if a capability is present
    pub fn has_capability(&self, cap_type: CapabilityType) -> bool {
        self.capabilities
            .get(&cap_type)
            .map(|r| r.capability_present == TriState::Yes)
            .unwrap_or(false)
    }

    /// Get all findings for a capability type
    pub fn findings_for(&self, cap_type: CapabilityType) -> Vec<&CapabilityFinding> {
        self.all_findings
            .iter()
            .filter(|f| f.capability_type == cap_type)
            .collect()
    }

    /// Get total capability count
    pub fn total_capability_count(&self) -> usize {
        self.capabilities
            .values()
            .filter(|r| r.capability_present == TriState::Yes)
            .count()
    }

    /// Get severity counts
    pub fn severity_counts(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for finding in &self.all_findings {
            *counts.entry(finding.severity.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Get findings by severity
    pub fn findings_by_severity(&self, severity: Severity) -> Vec<&CapabilityFinding> {
        self.all_findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    /// Get dormant findings
    pub fn dormant_findings(&self) -> Vec<&CapabilityFinding> {
        self.all_findings.iter().filter(|f| f.is_dormant).collect()
    }
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for capability detectors
pub trait CapabilityDetector: Send + Sync {
    /// Get the capability type this detector handles
    fn capability_type(&self) -> CapabilityType;

    /// Detect capabilities in the firmware artifact
    fn detect(&self, artifact: &FirmwareArtifact, raw_data: &[u8]) -> CoreResult<DetectorResult>;

    /// Get detector name
    fn name(&self) -> &'static str;

    /// Get detector description
    fn description(&self) -> &'static str;
}

/// Get all default detectors
pub fn default_detectors() -> Vec<Box<dyn CapabilityDetector>> {
    vec![
        Box::new(NetworkingDetector::new()),
        Box::new(TelemetryDetector::new()),
        Box::new(StorageDetector::new()),
        Box::new(UpdateDetector::new()),
        Box::new(IdentityDetector::new()),
        Box::new(CryptoDetector::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_result_creation() {
        let result = DetectorResult::new(CapabilityType::Networking);
        assert_eq!(result.capability_type, CapabilityType::Networking);
        assert_eq!(result.capability_present, TriState::Indeterminate);
    }

    #[test]
    fn test_analysis_result_merge() {
        let r1 = DetectorResult::new(CapabilityType::Networking);
        let r2 = DetectorResult::new(CapabilityType::Telemetry);

        let merged = AnalysisResult::merge(vec![r1, r2]);
        assert_eq!(merged.capabilities.len(), 2);
    }
}
