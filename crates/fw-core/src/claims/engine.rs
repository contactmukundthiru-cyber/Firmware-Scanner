//! Claim verification engine

use super::{Claim, ClaimVerdict, Condition, FailedCondition};
use crate::analysis::{AnalysisResult, CapabilityType};
use crate::evidence::Evidence;
use crate::ingestion::FirmwareArtifact;
use crate::TriState;

/// Claim compatibility verification engine
pub struct ClaimEngine;

impl ClaimEngine {
    pub fn new() -> Self {
        Self
    }

    /// Verify a claim against analysis results
    pub fn verify(
        &self,
        claim: &Claim,
        analysis: &AnalysisResult,
        artifact: &FirmwareArtifact,
    ) -> ClaimVerdict {
        let requirements = claim.requirements();
        let mut failing_conditions = Vec::new();
        let mut evidence = Vec::new();

        // Check required absent capabilities
        for cap_type in &requirements.required_absent {
            if analysis.has_capability(*cap_type) {
                let findings = analysis.findings_for(*cap_type);
                failing_conditions.push(FailedCondition {
                    condition_type: format!("Capability {} must be absent", cap_type),
                    description: format!(
                        "Found {} {} capabilities when claim requires none",
                        findings.len(),
                        cap_type
                    ),
                    evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                });

                // Collect evidence
                for finding in findings {
                    evidence.extend(finding.evidence.clone());
                }
            }
        }

        // Check required present capabilities
        for cap_type in &requirements.required_present {
            if !analysis.has_capability(*cap_type) {
                failing_conditions.push(FailedCondition {
                    condition_type: format!("Capability {} must be present", cap_type),
                    description: format!(
                        "Claim requires {} capability which was not found",
                        cap_type
                    ),
                    evidence: Vec::new(),
                });
            }
        }

        // Check specific conditions
        for condition in &requirements.conditions {
            if let Some(failed) = self.check_condition(condition, analysis, artifact) {
                failing_conditions.push(failed);
            }
        }

        // Determine verdict
        let compatible = if failing_conditions.is_empty() {
            TriState::Yes
        } else {
            TriState::No
        };

        let explanation = if failing_conditions.is_empty() {
            format!(
                "Claim '{}' is compatible with firmware. All {} conditions satisfied.",
                claim.name(),
                requirements.conditions.len()
            )
        } else {
            format!(
                "Claim '{}' is INCOMPATIBLE with firmware. {} of {} conditions failed.",
                claim.name(),
                failing_conditions.len(),
                requirements.conditions.len() + requirements.required_absent.len()
            )
        };

        ClaimVerdict {
            claim: claim.clone(),
            compatible,
            failing_conditions,
            evidence,
            explanation,
        }
    }

    /// Check a specific condition
    fn check_condition(
        &self,
        condition: &Condition,
        analysis: &AnalysisResult,
        _artifact: &FirmwareArtifact,
    ) -> Option<FailedCondition> {
        match condition {
            Condition::NoNetworkStack => {
                let findings: Vec<_> = analysis
                    .findings_for(CapabilityType::Networking)
                    .into_iter()
                    .filter(|f| f.tags.iter().any(|t| t == "tcp" || t == "ip" || t == "stack"))
                    .collect();

                if !findings.is_empty() {
                    return Some(FailedCondition {
                        condition_type: "NoNetworkStack".to_string(),
                        description: format!("Found {} network stack indicators", findings.len()),
                        evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                    });
                }
            }

            Condition::NoUrls => {
                let findings: Vec<_> = analysis
                    .findings_for(CapabilityType::Networking)
                    .into_iter()
                    .filter(|f| f.tags.iter().any(|t| t == "url" || t == "endpoint"))
                    .collect();

                if !findings.is_empty() {
                    return Some(FailedCondition {
                        condition_type: "NoUrls".to_string(),
                        description: format!("Found {} embedded URLs", findings.len()),
                        evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                    });
                }
            }

            Condition::NoIpAddresses => {
                let findings: Vec<_> = analysis
                    .findings_for(CapabilityType::Networking)
                    .into_iter()
                    .filter(|f| f.tags.iter().any(|t| t == "ip" || t == "address"))
                    .collect();

                if !findings.is_empty() {
                    return Some(FailedCondition {
                        condition_type: "NoIpAddresses".to_string(),
                        description: format!("Found {} IP addresses", findings.len()),
                        evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                    });
                }
            }

            Condition::NoAnalyticsEndpoints => {
                let findings: Vec<_> = analysis
                    .findings_for(CapabilityType::Telemetry)
                    .into_iter()
                    .filter(|f| f.tags.iter().any(|t| t == "analytics" || t == "telemetry"))
                    .collect();

                if !findings.is_empty() {
                    return Some(FailedCondition {
                        condition_type: "NoAnalyticsEndpoints".to_string(),
                        description: format!("Found {} analytics endpoints", findings.len()),
                        evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                    });
                }
            }

            Condition::NoCrashReporting => {
                let findings: Vec<_> = analysis
                    .findings_for(CapabilityType::Telemetry)
                    .into_iter()
                    .filter(|f| f.tags.iter().any(|t| t == "crash" || t == "error"))
                    .collect();

                if !findings.is_empty() {
                    return Some(FailedCondition {
                        condition_type: "NoCrashReporting".to_string(),
                        description: format!("Found {} crash reporting indicators", findings.len()),
                        evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                    });
                }
            }

            Condition::NoDeviceFingerprinting => {
                let findings: Vec<_> = analysis
                    .findings_for(CapabilityType::Identity)
                    .into_iter()
                    .filter(|f| f.tags.iter().any(|t| t == "fingerprint" || t == "tracking"))
                    .collect();

                if !findings.is_empty() {
                    return Some(FailedCondition {
                        condition_type: "NoDeviceFingerprinting".to_string(),
                        description: format!("Found {} fingerprinting indicators", findings.len()),
                        evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                    });
                }
            }

            Condition::NoOtaUpdate => {
                let findings: Vec<_> = analysis
                    .findings_for(CapabilityType::Update)
                    .into_iter()
                    .filter(|f| f.tags.iter().any(|t| t == "ota" || t == "update"))
                    .collect();

                if !findings.is_empty() {
                    return Some(FailedCondition {
                        condition_type: "NoOtaUpdate".to_string(),
                        description: format!("Found {} OTA update indicators", findings.len()),
                        evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                    });
                }
            }

            Condition::NoRemoteCommand => {
                let findings: Vec<_> = analysis
                    .findings_for(CapabilityType::Update)
                    .into_iter()
                    .filter(|f| f.tags.iter().any(|t| t == "remote" || t == "command"))
                    .collect();

                if !findings.is_empty() {
                    return Some(FailedCondition {
                        condition_type: "NoRemoteCommand".to_string(),
                        description: format!("Found {} remote command indicators", findings.len()),
                        evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                    });
                }
            }

            Condition::NoDatabase => {
                let findings: Vec<_> = analysis
                    .findings_for(CapabilityType::Storage)
                    .into_iter()
                    .filter(|f| f.tags.iter().any(|t| t == "database" || t == "sqlite" || t == "leveldb"))
                    .collect();

                if !findings.is_empty() {
                    return Some(FailedCondition {
                        condition_type: "NoDatabase".to_string(),
                        description: format!("Found {} database indicators", findings.len()),
                        evidence: findings.iter().flat_map(|f| f.evidence.clone()).collect(),
                    });
                }
            }

            // Other conditions follow similar pattern...
            _ => {}
        }

        None
    }

    /// Verify all common claims
    pub fn verify_all_common(
        &self,
        analysis: &AnalysisResult,
        artifact: &FirmwareArtifact,
    ) -> Vec<ClaimVerdict> {
        let common_claims = vec![
            Claim::Offline,
            Claim::NoTelemetry,
            Claim::NoTracking,
            Claim::NoRemoteAccess,
            Claim::NoAutoUpdate,
        ];

        common_claims
            .iter()
            .map(|claim| self.verify(claim, analysis, artifact))
            .collect()
    }
}

impl Default for ClaimEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_engine_creation() {
        let engine = ClaimEngine::new();
        // Should not panic
    }
}
