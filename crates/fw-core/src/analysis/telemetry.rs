//! Telemetry and data collection capability detection
//!
//! Detects analytics endpoints, crash reporters, metrics collectors, event batching

use super::{CapabilityDetector, CapabilityFinding, CapabilityType, DetectorResult};
use crate::evidence::Evidence;
use crate::ingestion::FirmwareArtifact;
use crate::{CoreResult, Severity, TriState};
use regex::Regex;
use std::collections::HashSet;

/// Telemetry capability detector
pub struct TelemetryDetector {
    analytics_domains: Vec<&'static str>,
    telemetry_patterns: Vec<Regex>,
}

impl TelemetryDetector {
    pub fn new() -> Self {
        Self {
            analytics_domains: vec![
                "google-analytics.com",
                "analytics.google.com",
                "amplitude.com",
                "mixpanel.com",
                "segment.com",
                "segment.io",
                "sentry.io",
                "crashlytics.com",
                "fabric.io",
                "appsflyer.com",
                "adjust.com",
                "branch.io",
                "firebase.google.com",
                "firebaseio.com",
                "newrelic.com",
                "datadog.com",
                "datadoghq.com",
                "splunk.com",
                "loggly.com",
                "bugsnag.com",
                "rollbar.com",
                "raygun.com",
                "instabug.com",
                "appcenter.ms",
                "aws.amazon.com/pinpoint",
                "mparticle.com",
                "heap.io",
                "fullstory.com",
                "hotjar.com",
            ],
            telemetry_patterns: vec![
                Regex::new(r"(analytics|telemetry|metrics)[_\-]?(send|upload|report|track)").unwrap(),
                Regex::new(r"(send|upload|report|track)[_\-]?(analytics|telemetry|metrics|event)").unwrap(),
                Regex::new(r"crash[_\-]?report").unwrap(),
                Regex::new(r"error[_\-]?report").unwrap(),
                Regex::new(r"usage[_\-]?(data|stats|metrics)").unwrap(),
                Regex::new(r"device[_\-]?(id|info|data)").unwrap(),
            ],
        }
    }

    /// Detect known analytics services
    fn detect_analytics_services(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);
        let text_lower = text.to_lowercase();

        for domain in &self.analytics_domains {
            if text_lower.contains(domain) {
                findings.push(CapabilityFinding {
                    id: format!("tel-{}", domain.replace('.', "-")),
                    capability_type: CapabilityType::Telemetry,
                    name: format!("Analytics Service: {}", domain),
                    description: format!("Connection to analytics/telemetry service: {}", domain),
                    severity: Severity::High,
                    confidence: 0.95,
                    is_dormant: false,
                    evidence: Vec::new(),
                    tags: vec!["analytics".to_string(), "telemetry".to_string(), domain.to_string()],
                });
            }
        }

        findings
    }

    /// Detect telemetry code patterns
    fn detect_telemetry_patterns(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        for pattern in &self.telemetry_patterns {
            if pattern.is_match(&text) {
                for mat in pattern.find_iter(&text) {
                    findings.push(CapabilityFinding {
                        id: format!("tel-pattern-{}", mat.start()),
                        capability_type: CapabilityType::Telemetry,
                        name: "Telemetry Code Pattern".to_string(),
                        description: format!("Telemetry-related code: {}", mat.as_str()),
                        severity: Severity::Medium,
                        confidence: 0.8,
                        is_dormant: false,
                        evidence: Vec::new(),
                        tags: vec!["telemetry".to_string(), "code".to_string()],
                    });
                    break; // Only one finding per pattern
                }
            }
        }

        findings
    }

    /// Detect crash reporting
    fn detect_crash_reporting(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        // Crashlytics
        if text.contains("crashlytics") || text.contains("Crashlytics") {
            findings.push(CapabilityFinding {
                id: "tel-crashlytics".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Firebase Crashlytics".to_string(),
                description: "Crash reporting via Firebase Crashlytics".to_string(),
                severity: Severity::High,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["crash".to_string(), "firebase".to_string()],
            });
        }

        // Sentry
        if text.contains("sentry.io") || text.contains("Sentry") || text.contains("@sentry") {
            findings.push(CapabilityFinding {
                id: "tel-sentry".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Sentry Error Tracking".to_string(),
                description: "Error/crash reporting via Sentry".to_string(),
                severity: Severity::High,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["crash".to_string(), "sentry".to_string()],
            });
        }

        // Bugsnag
        if text.contains("bugsnag") || text.contains("Bugsnag") {
            findings.push(CapabilityFinding {
                id: "tel-bugsnag".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Bugsnag Error Monitoring".to_string(),
                description: "Error monitoring via Bugsnag".to_string(),
                severity: Severity::High,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["crash".to_string(), "bugsnag".to_string()],
            });
        }

        // Generic crash dump patterns
        if text.contains("crash_dump") || text.contains("crashdump") || text.contains("core dump") {
            findings.push(CapabilityFinding {
                id: "tel-crash-dump".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Crash Dump Collection".to_string(),
                description: "System crash dump collection capability".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["crash".to_string(), "dump".to_string()],
            });
        }

        findings
    }

    /// Detect data serialization (often used for telemetry)
    fn detect_serialization(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        // Protobuf
        if text.contains("google.protobuf") || text.contains(".proto") || text.contains("protobuf") {
            findings.push(CapabilityFinding {
                id: "tel-protobuf".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Protocol Buffers".to_string(),
                description: "Protobuf serialization (commonly used for telemetry)".to_string(),
                severity: Severity::Low,
                confidence: 0.7,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["protobuf".to_string(), "serialization".to_string()],
            });
        }

        // CBOR
        if text.contains("CBOR") || text.contains("cbor") {
            findings.push(CapabilityFinding {
                id: "tel-cbor".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "CBOR Serialization".to_string(),
                description: "CBOR binary serialization format".to_string(),
                severity: Severity::Low,
                confidence: 0.7,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["cbor".to_string(), "serialization".to_string()],
            });
        }

        // MessagePack
        if text.contains("msgpack") || text.contains("MessagePack") {
            findings.push(CapabilityFinding {
                id: "tel-msgpack".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "MessagePack Serialization".to_string(),
                description: "MessagePack binary serialization format".to_string(),
                severity: Severity::Low,
                confidence: 0.7,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["msgpack".to_string(), "serialization".to_string()],
            });
        }

        findings
    }

    /// Detect event batching and queuing
    fn detect_event_queuing(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        // Event queue patterns
        if text.contains("event_queue") || text.contains("eventQueue") || text.contains("EventQueue") {
            findings.push(CapabilityFinding {
                id: "tel-event-queue".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Event Queue".to_string(),
                description: "Event queuing mechanism for batched upload".to_string(),
                severity: Severity::Medium,
                confidence: 0.8,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["event".to_string(), "queue".to_string()],
            });
        }

        // Batch upload patterns
        if text.contains("batch_upload") || text.contains("batchUpload") || text.contains("upload_batch") {
            findings.push(CapabilityFinding {
                id: "tel-batch-upload".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Batch Upload".to_string(),
                description: "Batched data upload capability".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["batch".to_string(), "upload".to_string()],
            });
        }

        // Retry logic
        if text.contains("retry_queue") || text.contains("retryQueue") || text.contains("upload_retry") {
            findings.push(CapabilityFinding {
                id: "tel-retry-queue".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Retry Queue".to_string(),
                description: "Upload retry mechanism".to_string(),
                severity: Severity::Medium,
                confidence: 0.8,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["retry".to_string(), "queue".to_string()],
            });
        }

        findings
    }

    /// Detect metrics collection
    fn detect_metrics_collection(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        // StatsD
        if text.contains("statsd") || text.contains("StatsD") {
            findings.push(CapabilityFinding {
                id: "tel-statsd".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "StatsD Metrics".to_string(),
                description: "StatsD metrics collection".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["statsd".to_string(), "metrics".to_string()],
            });
        }

        // Prometheus
        if text.contains("prometheus") || text.contains("/metrics") {
            findings.push(CapabilityFinding {
                id: "tel-prometheus".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Prometheus Metrics".to_string(),
                description: "Prometheus metrics endpoint".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["prometheus".to_string(), "metrics".to_string()],
            });
        }

        // Generic metrics patterns
        if text.contains("collect_metrics") || text.contains("collectMetrics") || text.contains("metrics_collector") {
            findings.push(CapabilityFinding {
                id: "tel-metrics-collector".to_string(),
                capability_type: CapabilityType::Telemetry,
                name: "Metrics Collector".to_string(),
                description: "Generic metrics collection capability".to_string(),
                severity: Severity::Medium,
                confidence: 0.8,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["metrics".to_string(), "collector".to_string()],
            });
        }

        findings
    }
}

impl Default for TelemetryDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityDetector for TelemetryDetector {
    fn capability_type(&self) -> CapabilityType {
        CapabilityType::Telemetry
    }

    fn detect(&self, artifact: &FirmwareArtifact, raw_data: &[u8]) -> CoreResult<DetectorResult> {
        let mut result = DetectorResult::new(CapabilityType::Telemetry);

        // Detect analytics services
        result.findings.extend(self.detect_analytics_services(raw_data));

        // Detect telemetry patterns
        result.findings.extend(self.detect_telemetry_patterns(raw_data));

        // Detect crash reporting
        result.findings.extend(self.detect_crash_reporting(raw_data));

        // Detect serialization
        result.findings.extend(self.detect_serialization(raw_data));

        // Detect event queuing
        result.findings.extend(self.detect_event_queuing(raw_data));

        // Detect metrics collection
        result.findings.extend(self.detect_metrics_collection(raw_data));

        // Deduplicate findings by ID
        let mut seen = HashSet::new();
        result.findings.retain(|f| seen.insert(f.id.clone()));

        // Set presence state
        if !result.findings.is_empty() {
            result.capability_present = TriState::Yes;

            let high_severity = result.findings.iter()
                .filter(|f| f.severity >= Severity::High)
                .count();

            result.summary = format!(
                "Found {} telemetry capabilities ({} high severity)",
                result.findings.len(),
                high_severity
            );
        } else {
            result.capability_present = TriState::No;
            result.summary = "No telemetry capabilities detected".to_string();
        }

        Ok(result)
    }

    fn name(&self) -> &'static str {
        "Telemetry Detector"
    }

    fn description(&self) -> &'static str {
        "Detects analytics services, crash reporters, metrics collectors, and data collection"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analytics_detection() {
        let detector = TelemetryDetector::new();
        let data = b"sending data to google-analytics.com";
        let findings = detector.detect_analytics_services(data);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_crash_reporting_detection() {
        let detector = TelemetryDetector::new();
        let data = b"initializing crashlytics SDK";
        let findings = detector.detect_crash_reporting(data);
        assert!(findings.iter().any(|f| f.id == "tel-crashlytics"));
    }
}
