//! Firmware Scanner Core Analysis Engine
//!
//! This crate provides the core analysis engine for detecting capabilities
//! in firmware images, verifying vendor claims, and preserving evidence.

pub mod analysis;
pub mod claims;
pub mod dormant;
pub mod evidence;
pub mod ingestion;
pub mod report;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

pub use analysis::{AnalysisConfig, AnalysisResult, CapabilityDetector};
pub use claims::{Claim, ClaimEngine, ClaimVerdict};
pub use evidence::{Evidence, EvidenceCollector};
pub use ingestion::{FirmwareArtifact, Ingester};

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Ingestion error: {0}")]
    Ingestion(String),

    #[error("Evidence error: {0}")]
    Evidence(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type CoreResult<T> = Result<T, CoreError>;

/// Complete scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Maximum recursion depth for nested containers
    pub max_recursion_depth: usize,
    /// Maximum file size to process (bytes)
    pub max_file_size: u64,
    /// Minimum string length for extraction
    pub min_string_length: usize,
    /// Enable dormant capability detection
    pub detect_dormant: bool,
    /// Claims to verify
    pub claims_to_verify: Vec<Claim>,
    /// Evidence context bytes (before/after)
    pub evidence_context_bytes: usize,
    /// Output directory for evidence
    pub evidence_output_dir: Option<PathBuf>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_recursion_depth: 10,
            max_file_size: 1024 * 1024 * 1024, // 1GB
            min_string_length: 4,
            detect_dormant: true,
            claims_to_verify: vec![
                Claim::Offline,
                Claim::NoTelemetry,
                Claim::NoTracking,
                Claim::NoRemoteAccess,
            ],
            evidence_context_bytes: 64,
            evidence_output_dir: None,
        }
    }
}

/// Complete scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub artifact: FirmwareArtifact,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub analysis: AnalysisResult,
    pub claim_verdicts: Vec<ClaimVerdict>,
    pub evidence: Vec<Evidence>,
    pub summary: ScanSummary,
}

/// Scan summary for quick overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_files_analyzed: usize,
    pub total_capabilities_found: usize,
    pub dormant_capabilities_found: usize,
    pub claims_verified: usize,
    pub claims_failed: usize,
    pub claims_indeterminate: usize,
    pub evidence_items: usize,
    pub severity_counts: HashMap<String, usize>,
}

/// Main scanner interface
pub struct Scanner {
    config: ScanConfig,
    ingester: Ingester,
    detectors: Vec<Box<dyn CapabilityDetector>>,
    claim_engine: ClaimEngine,
    evidence_collector: EvidenceCollector,
}

impl Scanner {
    /// Create a new scanner with default configuration
    pub fn new() -> Self {
        Self::with_config(ScanConfig::default())
    }

    /// Create a new scanner with custom configuration
    pub fn with_config(config: ScanConfig) -> Self {
        let ingester = Ingester::new(config.max_recursion_depth);
        let detectors = analysis::default_detectors();
        let claim_engine = ClaimEngine::new();
        let evidence_collector = EvidenceCollector::new(config.evidence_context_bytes);

        Self {
            config,
            ingester,
            detectors,
            claim_engine,
            evidence_collector,
        }
    }

    /// Scan firmware from file path
    pub fn scan_file(&self, path: &std::path::Path) -> CoreResult<ScanResult> {
        let data = std::fs::read(path)?;
        self.scan_bytes(&data, Some(path.to_string_lossy().to_string()))
    }

    /// Scan firmware from bytes
    pub fn scan_bytes(&self, data: &[u8], source_name: Option<String>) -> CoreResult<ScanResult> {
        let id = Uuid::new_v4();
        let started_at = Utc::now();

        // Ingest and parse the firmware
        let artifact = self.ingester.ingest(data, source_name)?;

        // Run all capability detectors
        let mut analysis_results = Vec::new();
        let mut all_evidence = Vec::new();

        for detector in &self.detectors {
            let result = detector.detect(&artifact, data)?;
            all_evidence.extend(result.evidence.clone());
            analysis_results.push(result);
        }

        // Merge analysis results
        let analysis = AnalysisResult::merge(analysis_results);

        // Verify claims
        let claim_verdicts: Vec<ClaimVerdict> = self
            .config
            .claims_to_verify
            .iter()
            .map(|claim| self.claim_engine.verify(claim, &analysis, &artifact))
            .collect();

        // Detect dormant capabilities if enabled
        let dormant_analysis = if self.config.detect_dormant {
            dormant::detect_dormant(&artifact, data, &analysis)
        } else {
            Vec::new()
        };

        // Collect all evidence with context
        let evidence = self.evidence_collector.collect_all(
            data,
            &analysis,
            &dormant_analysis,
            &claim_verdicts,
        );

        let completed_at = Utc::now();

        // Generate summary
        let summary = ScanSummary {
            total_files_analyzed: artifact.file_count(),
            total_capabilities_found: analysis.total_capability_count(),
            dormant_capabilities_found: dormant_analysis.len(),
            claims_verified: claim_verdicts.iter().filter(|v| v.is_compatible()).count(),
            claims_failed: claim_verdicts.iter().filter(|v| v.is_incompatible()).count(),
            claims_indeterminate: claim_verdicts.iter().filter(|v| v.is_indeterminate()).count(),
            evidence_items: evidence.len(),
            severity_counts: analysis.severity_counts(),
        };

        Ok(ScanResult {
            id,
            artifact,
            started_at,
            completed_at,
            analysis,
            claim_verdicts,
            evidence,
            summary,
        })
    }

    /// Get current configuration
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Add a custom detector
    pub fn add_detector(&mut self, detector: Box<dyn CapabilityDetector>) {
        self.detectors.push(detector);
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

/// TriState for claim compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriState {
    Yes,
    No,
    Indeterminate,
}

impl TriState {
    pub fn is_yes(&self) -> bool {
        matches!(self, TriState::Yes)
    }

    pub fn is_no(&self) -> bool {
        matches!(self, TriState::No)
    }

    pub fn is_indeterminate(&self) -> bool {
        matches!(self, TriState::Indeterminate)
    }
}

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = Scanner::new();
        assert_eq!(scanner.config().max_recursion_depth, 10);
    }

    #[test]
    fn test_tristate() {
        assert!(TriState::Yes.is_yes());
        assert!(TriState::No.is_no());
        assert!(TriState::Indeterminate.is_indeterminate());
    }
}
