//! Networking capability detection
//!
//! Detects TCP/IP stacks, socket APIs, HTTP clients, MQTT, CoAP, WebSockets, etc.

use super::{CapabilityDetector, CapabilityFinding, CapabilityType, DetectorResult};
use crate::evidence::Evidence;
use crate::ingestion::FirmwareArtifact;
use crate::{CoreResult, Severity, TriState};
use fw_signatures::{CapabilityCategory, SignatureDatabase, DEFAULT_DATABASE};
use regex::Regex;
use std::collections::HashSet;

/// Network capability detector
pub struct NetworkingDetector {
    url_regex: Regex,
    ip_regex: Regex,
}

impl NetworkingDetector {
    pub fn new() -> Self {
        Self {
            url_regex: Regex::new(r"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^\s\x00]*").unwrap(),
            ip_regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
        }
    }

    /// Detect network stack presence
    fn detect_network_stacks(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        // lwIP detection
        if text.contains("lwIP") || text.contains("lwip") {
            findings.push(CapabilityFinding {
                id: "net-lwip".to_string(),
                capability_type: CapabilityType::Networking,
                name: "lwIP TCP/IP Stack".to_string(),
                description: "Lightweight TCP/IP stack for embedded systems".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["tcp".to_string(), "ip".to_string(), "embedded".to_string()],
            });
        }

        // FreeRTOS+TCP
        if text.contains("FreeRTOS_IP") || text.contains("FreeRTOS+TCP") {
            findings.push(CapabilityFinding {
                id: "net-freertos-tcp".to_string(),
                capability_type: CapabilityType::Networking,
                name: "FreeRTOS+TCP".to_string(),
                description: "FreeRTOS TCP/IP network stack".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["freertos".to_string(), "tcp".to_string()],
            });
        }

        // uIP
        if text.contains("uip_init") || text.contains("uIP") {
            findings.push(CapabilityFinding {
                id: "net-uip".to_string(),
                capability_type: CapabilityType::Networking,
                name: "uIP Stack".to_string(),
                description: "Micro IP embedded TCP/IP stack".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["uip".to_string(), "embedded".to_string()],
            });
        }

        findings
    }

    /// Detect socket API usage
    fn detect_socket_api(&self, artifact: &FirmwareArtifact, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        let socket_functions = [
            ("socket", "Socket creation"),
            ("connect", "Socket connection"),
            ("bind", "Socket binding"),
            ("listen", "Socket listening"),
            ("accept", "Socket accept"),
            ("send", "Socket send"),
            ("recv", "Socket receive"),
            ("sendto", "UDP send"),
            ("recvfrom", "UDP receive"),
            ("getaddrinfo", "DNS resolution"),
            ("gethostbyname", "DNS lookup"),
        ];

        for (func, desc) in socket_functions {
            if text.contains(func) {
                findings.push(CapabilityFinding {
                    id: format!("net-socket-{}", func),
                    capability_type: CapabilityType::Networking,
                    name: format!("{} API", func),
                    description: desc.to_string(),
                    severity: Severity::Medium,
                    confidence: 0.85,
                    is_dormant: false,
                    evidence: Vec::new(),
                    tags: vec!["socket".to_string(), "api".to_string()],
                });
            }
        }

        findings
    }

    /// Detect HTTP client capabilities
    fn detect_http_client(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        // HTTP library detection
        if text.contains("libcurl") || text.contains("curl_easy") {
            findings.push(CapabilityFinding {
                id: "net-curl".to_string(),
                capability_type: CapabilityType::Networking,
                name: "libcurl HTTP Client".to_string(),
                description: "cURL library for HTTP/HTTPS communication".to_string(),
                severity: Severity::High,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["curl".to_string(), "http".to_string()],
            });
        }

        // HTTP headers
        if text.contains("User-Agent:") {
            findings.push(CapabilityFinding {
                id: "net-http-client".to_string(),
                capability_type: CapabilityType::Networking,
                name: "HTTP Client".to_string(),
                description: "HTTP client capability detected".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["http".to_string(), "client".to_string()],
            });
        }

        // Content-Type headers
        if text.contains("application/json") || text.contains("application/x-www-form") {
            findings.push(CapabilityFinding {
                id: "net-http-post".to_string(),
                capability_type: CapabilityType::Networking,
                name: "HTTP POST Capability".to_string(),
                description: "HTTP POST with data submission".to_string(),
                severity: Severity::Medium,
                confidence: 0.8,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["http".to_string(), "post".to_string()],
            });
        }

        findings
    }

    /// Extract URLs from firmware
    fn extract_urls(&self, data: &[u8]) -> Vec<(String, usize)> {
        let text = String::from_utf8_lossy(data);
        let mut urls = Vec::new();
        let mut seen = HashSet::new();

        for mat in self.url_regex.find_iter(&text) {
            let url = mat.as_str().to_string();
            if !seen.contains(&url) {
                seen.insert(url.clone());
                urls.push((url, mat.start()));
            }
        }

        urls
    }

    /// Extract IP addresses
    fn extract_ips(&self, data: &[u8]) -> Vec<(String, usize)> {
        let text = String::from_utf8_lossy(data);
        let mut ips = Vec::new();
        let mut seen = HashSet::new();

        for mat in self.ip_regex.find_iter(&text) {
            let ip = mat.as_str().to_string();
            // Filter out common false positives
            if !seen.contains(&ip)
                && !ip.starts_with("0.")
                && !ip.starts_with("255.")
                && ip != "0.0.0.0"
                && ip != "127.0.0.1"
            {
                seen.insert(ip.clone());
                ips.push((ip, mat.start()));
            }
        }

        ips
    }

    /// Detect IoT protocols
    fn detect_iot_protocols(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        // MQTT
        if text.contains("MQTT") || text.contains("mqtt://") || text.contains("MQTTClient") {
            findings.push(CapabilityFinding {
                id: "net-mqtt".to_string(),
                capability_type: CapabilityType::Networking,
                name: "MQTT Protocol".to_string(),
                description: "MQTT IoT messaging protocol support".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["mqtt".to_string(), "iot".to_string()],
            });
        }

        // CoAP
        if text.contains("coap://") || text.contains("CoAP") {
            findings.push(CapabilityFinding {
                id: "net-coap".to_string(),
                capability_type: CapabilityType::Networking,
                name: "CoAP Protocol".to_string(),
                description: "Constrained Application Protocol for IoT".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["coap".to_string(), "iot".to_string()],
            });
        }

        // WebSocket
        if text.contains("Sec-WebSocket") || text.contains("websocket") {
            findings.push(CapabilityFinding {
                id: "net-websocket".to_string(),
                capability_type: CapabilityType::Networking,
                name: "WebSocket Protocol".to_string(),
                description: "WebSocket bidirectional communication".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["websocket".to_string(), "realtime".to_string()],
            });
        }

        // gRPC/Protobuf
        if text.contains("grpc") || text.contains("protobuf") {
            findings.push(CapabilityFinding {
                id: "net-grpc".to_string(),
                capability_type: CapabilityType::Networking,
                name: "gRPC Protocol".to_string(),
                description: "gRPC remote procedure calls".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["grpc".to_string(), "rpc".to_string()],
            });
        }

        findings
    }

    /// Detect network drivers
    fn detect_network_drivers(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        // WiFi
        if text.contains("wlan") || text.contains("wifi") || text.contains("WiFi") || text.contains("802.11") {
            findings.push(CapabilityFinding {
                id: "net-wifi".to_string(),
                capability_type: CapabilityType::Networking,
                name: "WiFi Support".to_string(),
                description: "WiFi network interface capability".to_string(),
                severity: Severity::High,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["wifi".to_string(), "wireless".to_string()],
            });
        }

        // Ethernet
        if text.contains("eth0") || text.contains("ethernet") || text.contains("ethtool") {
            findings.push(CapabilityFinding {
                id: "net-ethernet".to_string(),
                capability_type: CapabilityType::Networking,
                name: "Ethernet Support".to_string(),
                description: "Ethernet network interface".to_string(),
                severity: Severity::Medium,
                confidence: 0.8,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["ethernet".to_string(), "wired".to_string()],
            });
        }

        // Cellular/LTE
        if text.contains("LTE") || text.contains("cellular") || text.contains("modem") || text.contains("4G") {
            findings.push(CapabilityFinding {
                id: "net-cellular".to_string(),
                capability_type: CapabilityType::Networking,
                name: "Cellular Support".to_string(),
                description: "Cellular/LTE network capability".to_string(),
                severity: Severity::High,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["cellular".to_string(), "lte".to_string()],
            });
        }

        // Bluetooth
        if text.contains("bluetooth") || text.contains("Bluetooth") || text.contains("BLE") || text.contains("hci0") {
            findings.push(CapabilityFinding {
                id: "net-bluetooth".to_string(),
                capability_type: CapabilityType::Networking,
                name: "Bluetooth Support".to_string(),
                description: "Bluetooth communication capability".to_string(),
                severity: Severity::Medium,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["bluetooth".to_string(), "wireless".to_string()],
            });
        }

        findings
    }
}

impl Default for NetworkingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityDetector for NetworkingDetector {
    fn capability_type(&self) -> CapabilityType {
        CapabilityType::Networking
    }

    fn detect(&self, artifact: &FirmwareArtifact, raw_data: &[u8]) -> CoreResult<DetectorResult> {
        let mut result = DetectorResult::new(CapabilityType::Networking);

        // Detect network stacks
        result.findings.extend(self.detect_network_stacks(raw_data));

        // Detect socket API
        result.findings.extend(self.detect_socket_api(artifact, raw_data));

        // Detect HTTP client
        result.findings.extend(self.detect_http_client(raw_data));

        // Detect IoT protocols
        result.findings.extend(self.detect_iot_protocols(raw_data));

        // Detect network drivers
        result.findings.extend(self.detect_network_drivers(raw_data));

        // Extract URLs
        let urls = self.extract_urls(raw_data);
        for (url, offset) in &urls {
            result.findings.push(CapabilityFinding {
                id: format!("net-url-{}", offset),
                capability_type: CapabilityType::Networking,
                name: "Embedded URL".to_string(),
                description: format!("URL found: {}", url),
                severity: Severity::High,
                confidence: 0.95,
                is_dormant: false,
                evidence: vec![Evidence {
                    id: uuid::Uuid::new_v4(),
                    finding_id: format!("net-url-{}", offset),
                    file_path: artifact.source_name.clone().unwrap_or_default(),
                    byte_offset: *offset as u64,
                    byte_length: url.len(),
                    content_hash: String::new(),
                    matched_data: url.as_bytes().to_vec(),
                    context_before: Vec::new(),
                    context_after: Vec::new(),
                    reproduction_notes: format!("URL at offset 0x{:x}", offset),
                }],
                tags: vec!["url".to_string(), "endpoint".to_string()],
            });
        }

        // Extract IPs
        let ips = self.extract_ips(raw_data);
        for (ip, offset) in &ips {
            result.findings.push(CapabilityFinding {
                id: format!("net-ip-{}", offset),
                capability_type: CapabilityType::Networking,
                name: "Embedded IP Address".to_string(),
                description: format!("IP address found: {}", ip),
                severity: Severity::Medium,
                confidence: 0.8,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["ip".to_string(), "address".to_string()],
            });
        }

        // Set presence state
        if !result.findings.is_empty() {
            result.capability_present = TriState::Yes;
            result.summary = format!(
                "Found {} networking capabilities including {} URLs and {} IP addresses",
                result.findings.len(),
                urls.len(),
                ips.len()
            );
        } else {
            result.capability_present = TriState::No;
            result.summary = "No networking capabilities detected".to_string();
        }

        Ok(result)
    }

    fn name(&self) -> &'static str {
        "Networking Detector"
    }

    fn description(&self) -> &'static str {
        "Detects TCP/IP stacks, socket APIs, HTTP clients, IoT protocols, and network interfaces"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_extraction() {
        let detector = NetworkingDetector::new();
        let data = b"connecting to https://api.example.com/data and http://192.168.1.1";
        let urls = detector.extract_urls(data);
        assert!(urls.iter().any(|(url, _)| url.contains("api.example.com")));
    }

    #[test]
    fn test_ip_extraction() {
        let detector = NetworkingDetector::new();
        let data = b"server at 192.168.1.100 and 10.0.0.1";
        let ips = detector.extract_ips(data);
        assert!(ips.iter().any(|(ip, _)| ip == "192.168.1.100"));
        assert!(ips.iter().any(|(ip, _)| ip == "10.0.0.1"));
    }
}
