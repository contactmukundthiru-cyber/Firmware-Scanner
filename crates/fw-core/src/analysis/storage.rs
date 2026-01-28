//! Storage and persistence capability detection

use super::{CapabilityDetector, CapabilityFinding, CapabilityType, DetectorResult};
use crate::ingestion::FirmwareArtifact;
use crate::{CoreResult, Severity, TriState};

pub struct StorageDetector;

impl StorageDetector {
    pub fn new() -> Self { Self }

    fn detect_databases(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("SQLite format 3") || text.contains("sqlite3") {
            findings.push(CapabilityFinding {
                id: "stor-sqlite".to_string(),
                capability_type: CapabilityType::Storage,
                name: "SQLite Database".to_string(),
                description: "SQLite embedded database".to_string(),
                severity: Severity::Medium,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["sqlite".to_string(), "database".to_string()],
            });
        }

        if text.contains("leveldb") || text.contains("LevelDB") {
            findings.push(CapabilityFinding {
                id: "stor-leveldb".to_string(),
                capability_type: CapabilityType::Storage,
                name: "LevelDB".to_string(),
                description: "LevelDB key-value store".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["leveldb".to_string(), "kvstore".to_string()],
            });
        }

        if text.contains("rocksdb") || text.contains("RocksDB") {
            findings.push(CapabilityFinding {
                id: "stor-rocksdb".to_string(),
                capability_type: CapabilityType::Storage,
                name: "RocksDB".to_string(),
                description: "RocksDB persistent storage".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["rocksdb".to_string(), "kvstore".to_string()],
            });
        }

        findings
    }

    fn detect_flash_storage(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("nvs_flash") || text.contains("NVS") {
            findings.push(CapabilityFinding {
                id: "stor-nvs".to_string(),
                capability_type: CapabilityType::Storage,
                name: "NVS Storage".to_string(),
                description: "Non-volatile storage partition".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["nvs".to_string(), "flash".to_string()],
            });
        }

        if text.contains("SPIFFS") || text.contains("spiffs") {
            findings.push(CapabilityFinding {
                id: "stor-spiffs".to_string(),
                capability_type: CapabilityType::Storage,
                name: "SPIFFS".to_string(),
                description: "SPI Flash File System".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["spiffs".to_string(), "flash".to_string()],
            });
        }

        if text.contains("littlefs") || text.contains("LittleFS") {
            findings.push(CapabilityFinding {
                id: "stor-littlefs".to_string(),
                capability_type: CapabilityType::Storage,
                name: "LittleFS".to_string(),
                description: "Little File System for embedded".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["littlefs".to_string(), "embedded".to_string()],
            });
        }

        findings
    }

    fn detect_logging(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("/var/log") || text.contains("syslog") || text.contains("journald") {
            findings.push(CapabilityFinding {
                id: "stor-syslog".to_string(),
                capability_type: CapabilityType::Storage,
                name: "System Logging".to_string(),
                description: "System log storage".to_string(),
                severity: Severity::Low,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["log".to_string(), "syslog".to_string()],
            });
        }

        if text.contains("log_rotate") || text.contains("logrotate") {
            findings.push(CapabilityFinding {
                id: "stor-logrotate".to_string(),
                capability_type: CapabilityType::Storage,
                name: "Log Rotation".to_string(),
                description: "Log rotation mechanism".to_string(),
                severity: Severity::Low,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["log".to_string(), "rotation".to_string()],
            });
        }

        findings
    }

    fn detect_caching(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("cache_dir") || text.contains("/cache") || text.contains("cacheDirectory") {
            findings.push(CapabilityFinding {
                id: "stor-cache".to_string(),
                capability_type: CapabilityType::Storage,
                name: "Cache Storage".to_string(),
                description: "Data caching capability".to_string(),
                severity: Severity::Low,
                confidence: 0.8,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["cache".to_string(), "storage".to_string()],
            });
        }

        findings
    }
}

impl Default for StorageDetector {
    fn default() -> Self { Self::new() }
}

impl CapabilityDetector for StorageDetector {
    fn capability_type(&self) -> CapabilityType { CapabilityType::Storage }

    fn detect(&self, _artifact: &FirmwareArtifact, raw_data: &[u8]) -> CoreResult<DetectorResult> {
        let mut result = DetectorResult::new(CapabilityType::Storage);

        result.findings.extend(self.detect_databases(raw_data));
        result.findings.extend(self.detect_flash_storage(raw_data));
        result.findings.extend(self.detect_logging(raw_data));
        result.findings.extend(self.detect_caching(raw_data));

        if !result.findings.is_empty() {
            result.capability_present = TriState::Yes;
            result.summary = format!("Found {} storage capabilities", result.findings.len());
        } else {
            result.capability_present = TriState::No;
            result.summary = "No storage capabilities detected".to_string();
        }

        Ok(result)
    }

    fn name(&self) -> &'static str { "Storage Detector" }
    fn description(&self) -> &'static str { "Detects databases, flash storage, logging, and caching" }
}
