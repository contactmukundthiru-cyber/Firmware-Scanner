//! Identity and tracking capability detection

use super::{CapabilityDetector, CapabilityFinding, CapabilityType, DetectorResult};
use crate::ingestion::FirmwareArtifact;
use crate::{CoreResult, Severity, TriState};
use regex::Regex;

pub struct IdentityDetector {
    uuid_regex: Regex,
    mac_regex: Regex,
}

impl IdentityDetector {
    pub fn new() -> Self {
        Self {
            uuid_regex: Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap(),
            mac_regex: Regex::new(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}").unwrap(),
        }
    }

    fn detect_device_ids(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("device_id") || text.contains("deviceId") || text.contains("device_identifier") {
            findings.push(CapabilityFinding {
                id: "id-device".to_string(),
                capability_type: CapabilityType::Identity,
                name: "Device ID".to_string(),
                description: "Device identifier collection".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["device".to_string(), "identifier".to_string()],
            });
        }

        if text.contains("serial_number") || text.contains("serialNumber") || text.contains("get_serial") {
            findings.push(CapabilityFinding {
                id: "id-serial".to_string(),
                capability_type: CapabilityType::Identity,
                name: "Serial Number".to_string(),
                description: "Serial number access".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["serial".to_string(), "identifier".to_string()],
            });
        }

        if text.contains("IMEI") || text.contains("imei") || text.contains("getImei") {
            findings.push(CapabilityFinding {
                id: "id-imei".to_string(),
                capability_type: CapabilityType::Identity,
                name: "IMEI".to_string(),
                description: "Mobile device IMEI access".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["imei".to_string(), "mobile".to_string()],
            });
        }

        if text.contains("ICCID") || text.contains("iccid") {
            findings.push(CapabilityFinding {
                id: "id-iccid".to_string(),
                capability_type: CapabilityType::Identity,
                name: "ICCID".to_string(),
                description: "SIM card identifier access".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["iccid".to_string(), "sim".to_string()],
            });
        }

        findings
    }

    fn detect_hardware_ids(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("mac_address") || text.contains("getMacAddress") || text.contains("hw_addr") {
            findings.push(CapabilityFinding {
                id: "id-mac".to_string(),
                capability_type: CapabilityType::Identity,
                name: "MAC Address".to_string(),
                description: "Hardware MAC address usage".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["mac".to_string(), "hardware".to_string()],
            });
        }

        if text.contains("cpuid") || text.contains("CPUID") || text.contains("cpu_id") {
            findings.push(CapabilityFinding {
                id: "id-cpuid".to_string(),
                capability_type: CapabilityType::Identity,
                name: "CPU ID".to_string(),
                description: "CPU identifier access".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["cpuid".to_string(), "hardware".to_string()],
            });
        }

        if text.contains("hardware_id") || text.contains("hwid") || text.contains("chip_id") {
            findings.push(CapabilityFinding {
                id: "id-hwid".to_string(),
                capability_type: CapabilityType::Identity,
                name: "Hardware ID".to_string(),
                description: "Hardware identifier collection".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["hwid".to_string(), "hardware".to_string()],
            });
        }

        findings
    }

    fn detect_fingerprinting(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("fingerprint") || text.contains("device_fingerprint") {
            findings.push(CapabilityFinding {
                id: "id-fingerprint".to_string(),
                capability_type: CapabilityType::Identity,
                name: "Device Fingerprinting".to_string(),
                description: "Device fingerprinting capability".to_string(),
                severity: Severity::High,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["fingerprint".to_string(), "tracking".to_string()],
            });
        }

        if text.contains("advertising_id") || text.contains("advertisingId") || text.contains("GAID") {
            findings.push(CapabilityFinding {
                id: "id-advertising".to_string(),
                capability_type: CapabilityType::Identity,
                name: "Advertising ID".to_string(),
                description: "Advertising identifier access".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["advertising".to_string(), "tracking".to_string()],
            });
        }

        findings
    }

    fn find_embedded_ids(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        // Find UUIDs
        let uuid_count = self.uuid_regex.find_iter(&text).count();
        if uuid_count > 0 {
            findings.push(CapabilityFinding {
                id: "id-uuid-embedded".to_string(),
                capability_type: CapabilityType::Identity,
                name: "Embedded UUIDs".to_string(),
                description: format!("Found {} embedded UUID patterns", uuid_count),
                severity: Severity::Low,
                confidence: 0.7,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["uuid".to_string(), "embedded".to_string()],
            });
        }

        findings
    }
}

impl Default for IdentityDetector {
    fn default() -> Self { Self::new() }
}

impl CapabilityDetector for IdentityDetector {
    fn capability_type(&self) -> CapabilityType { CapabilityType::Identity }

    fn detect(&self, _artifact: &FirmwareArtifact, raw_data: &[u8]) -> CoreResult<DetectorResult> {
        let mut result = DetectorResult::new(CapabilityType::Identity);

        result.findings.extend(self.detect_device_ids(raw_data));
        result.findings.extend(self.detect_hardware_ids(raw_data));
        result.findings.extend(self.detect_fingerprinting(raw_data));
        result.findings.extend(self.find_embedded_ids(raw_data));

        if !result.findings.is_empty() {
            result.capability_present = TriState::Yes;
            result.summary = format!("Found {} identity/tracking capabilities", result.findings.len());
        } else {
            result.capability_present = TriState::No;
            result.summary = "No identity capabilities detected".to_string();
        }

        Ok(result)
    }

    fn name(&self) -> &'static str { "Identity Detector" }
    fn description(&self) -> &'static str { "Detects device IDs, hardware fingerprinting, and tracking" }
}
