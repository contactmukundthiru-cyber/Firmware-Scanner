//! Cryptography capability detection

use super::{CapabilityDetector, CapabilityFinding, CapabilityType, DetectorResult};
use crate::ingestion::FirmwareArtifact;
use crate::{CoreResult, Severity, TriState};

pub struct CryptoDetector;

impl CryptoDetector {
    pub fn new() -> Self { Self }

    fn detect_tls_libraries(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("OpenSSL") || text.contains("openssl") {
            findings.push(CapabilityFinding {
                id: "crypto-openssl".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "OpenSSL".to_string(),
                description: "OpenSSL cryptographic library".to_string(),
                severity: Severity::Info,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["openssl".to_string(), "tls".to_string()],
            });
        }

        if text.contains("mbedtls") || text.contains("mbedTLS") || text.contains("mbed TLS") {
            findings.push(CapabilityFinding {
                id: "crypto-mbedtls".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "mbedTLS".to_string(),
                description: "mbedTLS embedded crypto library".to_string(),
                severity: Severity::Info,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["mbedtls".to_string(), "embedded".to_string()],
            });
        }

        if text.contains("wolfSSL") || text.contains("wolfssl") || text.contains("CyaSSL") {
            findings.push(CapabilityFinding {
                id: "crypto-wolfssl".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "wolfSSL".to_string(),
                description: "wolfSSL TLS library".to_string(),
                severity: Severity::Info,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["wolfssl".to_string(), "tls".to_string()],
            });
        }

        if text.contains("BearSSL") || text.contains("bearssl") {
            findings.push(CapabilityFinding {
                id: "crypto-bearssl".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "BearSSL".to_string(),
                description: "BearSSL TLS library".to_string(),
                severity: Severity::Info,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["bearssl".to_string(), "tls".to_string()],
            });
        }

        findings
    }

    fn detect_crypto_primitives(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("AES") || text.contains("aes_") || text.contains("AES_encrypt") {
            findings.push(CapabilityFinding {
                id: "crypto-aes".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "AES Encryption".to_string(),
                description: "AES symmetric encryption".to_string(),
                severity: Severity::Info,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["aes".to_string(), "symmetric".to_string()],
            });
        }

        if text.contains("RSA") || text.contains("rsa_") || text.contains("RSA_public") {
            findings.push(CapabilityFinding {
                id: "crypto-rsa".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "RSA Crypto".to_string(),
                description: "RSA asymmetric cryptography".to_string(),
                severity: Severity::Info,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["rsa".to_string(), "asymmetric".to_string()],
            });
        }

        if text.contains("ECDSA") || text.contains("ecdsa") || text.contains("EC_KEY") {
            findings.push(CapabilityFinding {
                id: "crypto-ecdsa".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "ECDSA".to_string(),
                description: "Elliptic curve digital signatures".to_string(),
                severity: Severity::Info,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["ecdsa".to_string(), "ecc".to_string()],
            });
        }

        if text.contains("SHA256") || text.contains("sha256") || text.contains("SHA-256") {
            findings.push(CapabilityFinding {
                id: "crypto-sha256".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "SHA-256".to_string(),
                description: "SHA-256 hash function".to_string(),
                severity: Severity::Info,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["sha256".to_string(), "hash".to_string()],
            });
        }

        findings
    }

    fn detect_key_material(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();

        if data.windows(27).any(|w| w == b"-----BEGIN CERTIFICATE-----") {
            findings.push(CapabilityFinding {
                id: "crypto-cert".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "X.509 Certificate".to_string(),
                description: "Embedded X.509 certificate".to_string(),
                severity: Severity::Medium,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["x509".to_string(), "certificate".to_string()],
            });
        }

        if data.windows(31).any(|w| w == b"-----BEGIN RSA PRIVATE KEY-----") ||
           data.windows(27).any(|w| w == b"-----BEGIN PRIVATE KEY-----") {
            findings.push(CapabilityFinding {
                id: "crypto-privkey".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "Private Key".to_string(),
                description: "Embedded private key material - CRITICAL".to_string(),
                severity: Severity::Critical,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["private".to_string(), "key".to_string()],
            });
        }

        if data.windows(26).any(|w| w == b"-----BEGIN PUBLIC KEY-----") {
            findings.push(CapabilityFinding {
                id: "crypto-pubkey".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "Public Key".to_string(),
                description: "Embedded public key".to_string(),
                severity: Severity::Low,
                confidence: 0.95,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["public".to_string(), "key".to_string()],
            });
        }

        findings
    }

    fn detect_secure_boot(&self, data: &[u8]) -> Vec<CapabilityFinding> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(data);

        if text.contains("secure_boot") || text.contains("secureboot") || text.contains("Secure Boot") {
            findings.push(CapabilityFinding {
                id: "crypto-secureboot".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "Secure Boot".to_string(),
                description: "Secure boot mechanism".to_string(),
                severity: Severity::Info,
                confidence: 0.9,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["secure".to_string(), "boot".to_string()],
            });
        }

        if text.contains("code_signing") || text.contains("signature_verify") || text.contains("verify_signature") {
            findings.push(CapabilityFinding {
                id: "crypto-codesign".to_string(),
                capability_type: CapabilityType::Crypto,
                name: "Code Signing".to_string(),
                description: "Code signature verification".to_string(),
                severity: Severity::Info,
                confidence: 0.85,
                is_dormant: false,
                evidence: Vec::new(),
                tags: vec!["signing".to_string(), "verify".to_string()],
            });
        }

        findings
    }
}

impl Default for CryptoDetector {
    fn default() -> Self { Self::new() }
}

impl CapabilityDetector for CryptoDetector {
    fn capability_type(&self) -> CapabilityType { CapabilityType::Crypto }

    fn detect(&self, _artifact: &FirmwareArtifact, raw_data: &[u8]) -> CoreResult<DetectorResult> {
        let mut result = DetectorResult::new(CapabilityType::Crypto);

        result.findings.extend(self.detect_tls_libraries(raw_data));
        result.findings.extend(self.detect_crypto_primitives(raw_data));
        result.findings.extend(self.detect_key_material(raw_data));
        result.findings.extend(self.detect_secure_boot(raw_data));

        if !result.findings.is_empty() {
            result.capability_present = TriState::Yes;
            let critical = result.findings.iter().filter(|f| f.severity == Severity::Critical).count();
            if critical > 0 {
                result.summary = format!("Found {} crypto capabilities ({} CRITICAL - embedded keys!)", result.findings.len(), critical);
            } else {
                result.summary = format!("Found {} cryptographic capabilities", result.findings.len());
            }
        } else {
            result.capability_present = TriState::Indeterminate;
            result.summary = "No explicit crypto detected (may use hardware)".to_string();
        }

        Ok(result)
    }

    fn name(&self) -> &'static str { "Crypto Detector" }
    fn description(&self) -> &'static str { "Detects TLS libraries, crypto primitives, and key material" }
}
