//! Update and remote control capability detection

use super::{CapabilityDetector, CapabilityFinding, CapabilityType, DetectorResult};
use crate::ingestion::FirmwareArtifact;
use crate::{CoreResult, Severity, TriState};

pub struct UpdateDetector;

impl UpdateDetector {
    pub fn new() -> Self { Self }

    fn detect_ota(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("OTA") || text.contains("ota_update") || text.contains("otaUpdate") {
            findings.push(CapabilityFinding {
                id: "upd-ota".to_string(),
                capability_type: CapabilityType::Update,
                name: "OTA Update".to_string(),
                description: "Over-the-air update capability".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["ota".to_string(), "update".to_string()],
            });
        }

        if text.contains("firmware_update") || text.contains("firmwareUpdate") || text.contains("fwupdate") {
            findings.push(CapabilityFinding {
                id: "upd-firmware".to_string(),
                capability_type: CapabilityType::Update,
                name: "Firmware Update".to_string(),
                description: "Firmware update mechanism".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["firmware".to_string(), "update".to_string()],
            });
        }

        findings
    }

    fn detect_update_frameworks(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("swupdate") || text.contains("SWUpdate") {
            findings.push(CapabilityFinding {
                id: "upd-swupdate".to_string(),
                capability_type: CapabilityType::Update,
                name: "SWUpdate".to_string(),
                description: "SWUpdate Linux update framework".to_string(),
                severity: Severity::High,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["swupdate".to_string(), "linux".to_string()],
            });
        }

        if text.contains("RAUC") || text.contains("rauc") {
            findings.push(CapabilityFinding {
                id: "upd-rauc".to_string(),
                capability_type: CapabilityType::Update,
                name: "RAUC".to_string(),
                description: "RAUC safe update controller".to_string(),
                severity: Severity::High,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["rauc".to_string(), "update".to_string()],
            });
        }

        if text.contains("mender") || text.contains("Mender") {
            findings.push(CapabilityFinding {
                id: "upd-mender".to_string(),
                capability_type: CapabilityType::Update,
                name: "Mender".to_string(),
                description: "Mender OTA update".to_string(),
                severity: Severity::High,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["mender".to_string(), "ota".to_string()],
            });
        }

        findings
    }

    fn detect_remote_control(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("remote_cmd") || text.contains("remoteCommand") || text.contains("execute_command") {
            findings.push(CapabilityFinding {
                id: "upd-remote-cmd".to_string(),
                capability_type: CapabilityType::Update,
                name: "Remote Command Execution".to_string(),
                description: "Remote command execution capability".to_string(),
                severity: Severity::Critical,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["remote".to_string(), "command".to_string()],
            });
        }

        if text.contains("feature_flag") || text.contains("featureFlag") || text.contains("feature_toggle") {
            findings.push(CapabilityFinding {
                id: "upd-feature-flag".to_string(),
                capability_type: CapabilityType::Update,
                name: "Feature Flags".to_string(),
                description: "Remote feature flag control".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["feature".to_string(), "flag".to_string()],
            });
        }

        if text.contains("kill_switch") || text.contains("killSwitch") || text.contains("remote_disable") {
            findings.push(CapabilityFinding {
                id: "upd-kill-switch".to_string(),
                capability_type: CapabilityType::Update,
                name: "Kill Switch".to_string(),
                description: "Remote device disable capability".to_string(),
                severity: Severity::Critical,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["kill".to_string(), "switch".to_string()],
            });
        }

        findings
    }

    fn detect_rollback(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("rollback") || text.contains("revert_firmware") {
            findings.push(CapabilityFinding {
                id: "upd-rollback".to_string(),
                capability_type: CapabilityType::Update,
                name: "Rollback Capability".to_string(),
                description: "Firmware rollback mechanism".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["rollback".to_string(), "recovery".to_string()],
            });
        }

        if text.contains("slot_a") || text.contains("slot_b") || text.contains("boot_slot") {
            findings.push(CapabilityFinding {
                id: "upd-ab-slot".to_string(),
                capability_type: CapabilityType::Update,
                name: "A/B Partition".to_string(),
                description: "A/B partition update scheme".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["ab".to_string(), "partition".to_string()],
            });
        }

        findings
    }
}

impl Default for UpdateDetector {
    fn default() -> Self { Self::new() }
}

impl CapabilityDetector for UpdateDetector {
    fn capability_type(&self) -> CapabilityType { CapabilityType::Update }

    fn detect(&self, _artifact: &FirmwareArtifact, raw_data: &[u8]) -> CoreResult<DetectorResult> {
        let mut result = DetectorResult::new(CapabilityType::Update);

        result.findings.extend(self.detect_ota(raw_data));
        result.findings.extend(self.detect_update_frameworks(raw_data));
        result.findings.extend(self.detect_remote_control(raw_data));
        result.findings.extend(self.detect_rollback(raw_data));

        if !result.findings.is_empty() {
            result.capability_present = TriState::Yes;
            let critical = result.findings.iter().filter(|f| f.severity == Severity::Critical).count();
            result.summary = format!("Found {} update/remote capabilities ({} critical)", result.findings.len(), critical);
        } else {
            result.capability_present = TriState::No;
            result.summary = "No update capabilities detected".to_string();
        }

        Ok(result)
    }

    fn name(&self) -> &'static str { "Update Detector" }
    fn description(&self) -> &'static str { "Detects OTA, firmware updates, and remote control" }
}
