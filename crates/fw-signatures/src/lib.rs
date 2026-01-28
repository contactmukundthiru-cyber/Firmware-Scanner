//! Signature database for firmware capability detection
//!
//! This crate provides pattern matching for detecting networking stacks,
//! telemetry components, cryptographic libraries, and other capabilities.

pub mod magic;
pub mod patterns;
pub mod strings;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Pattern compilation error: {0}")]
    PatternCompilation(String),

    #[error("Invalid signature format: {0}")]
    InvalidFormat(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type SignatureResult<T> = Result<T, SignatureError>;

/// Capability category for grouping signatures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityCategory {
    Networking,
    Telemetry,
    Storage,
    Update,
    Identity,
    Crypto,
    Debug,
    Remote,
}

/// A signature pattern for capability detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub category: CapabilityCategory,
    pub description: String,
    pub pattern_type: PatternType,
    pub pattern: String,
    pub confidence: f32,
    pub severity: Severity,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternType {
    /// Exact byte sequence
    Bytes,
    /// ASCII/UTF-8 string
    String,
    /// Regular expression
    Regex,
    /// Symbol name (from ELF/PE)
    Symbol,
    /// Imported function name
    Import,
    /// Exported function name
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Match result from signature detection
#[derive(Debug, Clone)]
pub struct SignatureMatch {
    pub signature_id: String,
    pub signature_name: String,
    pub category: CapabilityCategory,
    pub offset: u64,
    pub length: usize,
    pub matched_data: Vec<u8>,
    pub confidence: f32,
    pub severity: Severity,
    pub context: MatchContext,
}

#[derive(Debug, Clone, Default)]
pub struct MatchContext {
    pub file_path: Option<String>,
    pub section: Option<String>,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

/// Compiled signature database for fast matching
pub struct SignatureDatabase {
    signatures: Vec<Signature>,
    string_matcher: AhoCorasick,
    string_sig_indices: Vec<usize>,
    regex_patterns: Vec<(usize, Regex)>,
    symbol_patterns: HashMap<String, Vec<usize>>,
    import_patterns: HashMap<String, Vec<usize>>,
}

impl SignatureDatabase {
    /// Create a new signature database from signatures
    pub fn new(signatures: Vec<Signature>) -> SignatureResult<Self> {
        let mut string_patterns = Vec::new();
        let mut string_sig_indices = Vec::new();
        let mut regex_patterns = Vec::new();
        let mut symbol_patterns: HashMap<String, Vec<usize>> = HashMap::new();
        let mut import_patterns: HashMap<String, Vec<usize>> = HashMap::new();

        for (idx, sig) in signatures.iter().enumerate() {
            match sig.pattern_type {
                PatternType::String | PatternType::Bytes => {
                    let pattern = if sig.pattern_type == PatternType::Bytes {
                        hex::decode(&sig.pattern)
                            .map_err(|e| SignatureError::PatternCompilation(e.to_string()))?
                    } else {
                        sig.pattern.as_bytes().to_vec()
                    };
                    string_patterns.push(pattern);
                    string_sig_indices.push(idx);
                }
                PatternType::Regex => {
                    let re = Regex::new(&sig.pattern)
                        .map_err(|e| SignatureError::PatternCompilation(e.to_string()))?;
                    regex_patterns.push((idx, re));
                }
                PatternType::Symbol | PatternType::Export => {
                    symbol_patterns
                        .entry(sig.pattern.clone())
                        .or_default()
                        .push(idx);
                }
                PatternType::Import => {
                    import_patterns
                        .entry(sig.pattern.clone())
                        .or_default()
                        .push(idx);
                }
            }
        }

        let string_matcher = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&string_patterns)
            .map_err(|e| SignatureError::PatternCompilation(e.to_string()))?;

        Ok(Self {
            signatures,
            string_matcher,
            string_sig_indices,
            regex_patterns,
            symbol_patterns,
            import_patterns,
        })
    }

    /// Load default signatures
    pub fn default_database() -> SignatureResult<Self> {
        let signatures = get_default_signatures();
        Self::new(signatures)
    }

    /// Scan binary data for matches
    pub fn scan(&self, data: &[u8], context: MatchContext) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        // Aho-Corasick multi-pattern matching for strings/bytes
        for mat in self.string_matcher.find_iter(data) {
            let sig_idx = self.string_sig_indices[mat.pattern().as_usize()];
            let sig = &self.signatures[sig_idx];

            let start = mat.start();
            let end = mat.end();
            let matched_data = data[start..end].to_vec();

            // Get context bytes
            let before_start = start.saturating_sub(32);
            let after_end = std::cmp::min(end + 32, data.len());

            let mut ctx = context.clone();
            ctx.before = data[before_start..start].to_vec();
            ctx.after = data[end..after_end].to_vec();

            matches.push(SignatureMatch {
                signature_id: sig.id.clone(),
                signature_name: sig.name.clone(),
                category: sig.category,
                offset: start as u64,
                length: end - start,
                matched_data,
                confidence: sig.confidence,
                severity: sig.severity,
                context: ctx,
            });
        }

        // Regex matching (only on reasonable-sized data to avoid DoS)
        if data.len() < 10 * 1024 * 1024 {
            // < 10MB
            let data_str = String::from_utf8_lossy(data);
            for (sig_idx, re) in &self.regex_patterns {
                for mat in re.find_iter(&data_str) {
                    let sig = &self.signatures[*sig_idx];

                    let start = mat.start();
                    let end = mat.end();

                    matches.push(SignatureMatch {
                        signature_id: sig.id.clone(),
                        signature_name: sig.name.clone(),
                        category: sig.category,
                        offset: start as u64,
                        length: end - start,
                        matched_data: mat.as_str().as_bytes().to_vec(),
                        confidence: sig.confidence,
                        severity: sig.severity,
                        context: context.clone(),
                    });
                }
            }
        }

        matches
    }

    /// Check symbols against signature database
    pub fn check_symbols(&self, symbols: &[String], context: MatchContext) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        for symbol in symbols {
            if let Some(sig_indices) = self.symbol_patterns.get(symbol) {
                for &idx in sig_indices {
                    let sig = &self.signatures[idx];
                    matches.push(SignatureMatch {
                        signature_id: sig.id.clone(),
                        signature_name: sig.name.clone(),
                        category: sig.category,
                        offset: 0,
                        length: symbol.len(),
                        matched_data: symbol.as_bytes().to_vec(),
                        confidence: sig.confidence,
                        severity: sig.severity,
                        context: context.clone(),
                    });
                }
            }
        }

        matches
    }

    /// Check imports against signature database
    pub fn check_imports(&self, imports: &[String], context: MatchContext) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        for import in imports {
            if let Some(sig_indices) = self.import_patterns.get(import) {
                for &idx in sig_indices {
                    let sig = &self.signatures[idx];
                    matches.push(SignatureMatch {
                        signature_id: sig.id.clone(),
                        signature_name: sig.name.clone(),
                        category: sig.category,
                        offset: 0,
                        length: import.len(),
                        matched_data: import.as_bytes().to_vec(),
                        confidence: sig.confidence,
                        severity: sig.severity,
                        context: context.clone(),
                    });
                }
            }
        }

        matches
    }

    /// Get all signatures
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Get signatures by category
    pub fn signatures_by_category(&self, category: CapabilityCategory) -> Vec<&Signature> {
        self.signatures
            .iter()
            .filter(|s| s.category == category)
            .collect()
    }
}

/// Get default built-in signatures
pub fn get_default_signatures() -> Vec<Signature> {
    let mut sigs = Vec::new();

    // Networking signatures
    sigs.extend(networking_signatures());
    sigs.extend(telemetry_signatures());
    sigs.extend(storage_signatures());
    sigs.extend(update_signatures());
    sigs.extend(identity_signatures());
    sigs.extend(crypto_signatures());

    sigs
}

fn networking_signatures() -> Vec<Signature> {
    vec![
        // TCP/IP Stack indicators
        Signature {
            id: "net-lwip".to_string(),
            name: "lwIP TCP/IP Stack".to_string(),
            category: CapabilityCategory::Networking,
            description: "Lightweight IP (lwIP) embedded TCP/IP stack".to_string(),
            pattern_type: PatternType::String,
            pattern: "lwIP".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["tcp".to_string(), "ip".to_string(), "embedded".to_string()],
        },
        Signature {
            id: "net-socket-syscall".to_string(),
            name: "Socket System Call".to_string(),
            category: CapabilityCategory::Networking,
            description: "BSD socket API usage".to_string(),
            pattern_type: PatternType::Symbol,
            pattern: "socket".to_string(),
            confidence: 0.95,
            severity: Severity::Medium,
            tags: vec!["socket".to_string(), "network".to_string()],
        },
        Signature {
            id: "net-connect".to_string(),
            name: "Connect System Call".to_string(),
            category: CapabilityCategory::Networking,
            description: "Network connect capability".to_string(),
            pattern_type: PatternType::Symbol,
            pattern: "connect".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["socket".to_string(), "connect".to_string()],
        },
        Signature {
            id: "net-send".to_string(),
            name: "Send System Call".to_string(),
            category: CapabilityCategory::Networking,
            description: "Network send capability".to_string(),
            pattern_type: PatternType::Symbol,
            pattern: "send".to_string(),
            confidence: 0.85,
            severity: Severity::Low,
            tags: vec!["socket".to_string(), "send".to_string()],
        },
        Signature {
            id: "net-recv".to_string(),
            name: "Receive System Call".to_string(),
            category: CapabilityCategory::Networking,
            description: "Network receive capability".to_string(),
            pattern_type: PatternType::Symbol,
            pattern: "recv".to_string(),
            confidence: 0.85,
            severity: Severity::Low,
            tags: vec!["socket".to_string(), "recv".to_string()],
        },
        Signature {
            id: "net-http-client".to_string(),
            name: "HTTP Client".to_string(),
            category: CapabilityCategory::Networking,
            description: "HTTP client capability detected".to_string(),
            pattern_type: PatternType::String,
            pattern: "User-Agent:".to_string(),
            confidence: 0.85,
            severity: Severity::Medium,
            tags: vec!["http".to_string(), "client".to_string()],
        },
        Signature {
            id: "net-https-url".to_string(),
            name: "HTTPS URL".to_string(),
            category: CapabilityCategory::Networking,
            description: "HTTPS URL pattern found".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"https://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}".to_string(),
            confidence: 0.95,
            severity: Severity::High,
            tags: vec!["https".to_string(), "url".to_string()],
        },
        Signature {
            id: "net-mqtt".to_string(),
            name: "MQTT Protocol".to_string(),
            category: CapabilityCategory::Networking,
            description: "MQTT IoT messaging protocol".to_string(),
            pattern_type: PatternType::String,
            pattern: "MQTT".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["mqtt".to_string(), "iot".to_string()],
        },
        Signature {
            id: "net-coap".to_string(),
            name: "CoAP Protocol".to_string(),
            category: CapabilityCategory::Networking,
            description: "CoAP constrained application protocol".to_string(),
            pattern_type: PatternType::String,
            pattern: "coap://".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["coap".to_string(), "iot".to_string()],
        },
        Signature {
            id: "net-websocket".to_string(),
            name: "WebSocket Protocol".to_string(),
            category: CapabilityCategory::Networking,
            description: "WebSocket bidirectional communication".to_string(),
            pattern_type: PatternType::String,
            pattern: "Sec-WebSocket".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["websocket".to_string(), "realtime".to_string()],
        },
        Signature {
            id: "net-dns-resolver".to_string(),
            name: "DNS Resolver".to_string(),
            category: CapabilityCategory::Networking,
            description: "DNS resolution capability".to_string(),
            pattern_type: PatternType::Symbol,
            pattern: "getaddrinfo".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["dns".to_string(), "resolver".to_string()],
        },
        Signature {
            id: "net-curl".to_string(),
            name: "libcurl".to_string(),
            category: CapabilityCategory::Networking,
            description: "cURL library for HTTP/HTTPS".to_string(),
            pattern_type: PatternType::String,
            pattern: "libcurl".to_string(),
            confidence: 0.95,
            severity: Severity::Medium,
            tags: vec!["curl".to_string(), "http".to_string()],
        },
    ]
}

fn telemetry_signatures() -> Vec<Signature> {
    vec![
        Signature {
            id: "tel-analytics".to_string(),
            name: "Analytics Endpoint".to_string(),
            category: CapabilityCategory::Telemetry,
            description: "Analytics data collection endpoint".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"(analytics|telemetry|metrics)\.(google|amazon|azure|cloudflare)".to_string(),
            confidence: 0.95,
            severity: Severity::High,
            tags: vec!["analytics".to_string(), "telemetry".to_string()],
        },
        Signature {
            id: "tel-crash-report".to_string(),
            name: "Crash Reporter".to_string(),
            category: CapabilityCategory::Telemetry,
            description: "Crash reporting functionality".to_string(),
            pattern_type: PatternType::String,
            pattern: "crashlytics".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["crash".to_string(), "reporting".to_string()],
        },
        Signature {
            id: "tel-sentry".to_string(),
            name: "Sentry Error Tracking".to_string(),
            category: CapabilityCategory::Telemetry,
            description: "Sentry error tracking SDK".to_string(),
            pattern_type: PatternType::String,
            pattern: "sentry.io".to_string(),
            confidence: 0.95,
            severity: Severity::High,
            tags: vec!["sentry".to_string(), "error".to_string()],
        },
        Signature {
            id: "tel-protobuf".to_string(),
            name: "Protocol Buffers".to_string(),
            category: CapabilityCategory::Telemetry,
            description: "Protobuf serialization (often used for telemetry)".to_string(),
            pattern_type: PatternType::String,
            pattern: "google.protobuf".to_string(),
            confidence: 0.7,
            severity: Severity::Low,
            tags: vec!["protobuf".to_string(), "serialization".to_string()],
        },
        Signature {
            id: "tel-json-upload".to_string(),
            name: "JSON Upload Pattern".to_string(),
            category: CapabilityCategory::Telemetry,
            description: "JSON content type for data upload".to_string(),
            pattern_type: PatternType::String,
            pattern: "application/json".to_string(),
            confidence: 0.5,
            severity: Severity::Low,
            tags: vec!["json".to_string(), "upload".to_string()],
        },
        Signature {
            id: "tel-device-id".to_string(),
            name: "Device ID Collection".to_string(),
            category: CapabilityCategory::Telemetry,
            description: "Device identifier collection pattern".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"device[_-]?id|deviceId|device_identifier".to_string(),
            confidence: 0.85,
            severity: Severity::High,
            tags: vec!["device".to_string(), "identifier".to_string()],
        },
        Signature {
            id: "tel-mixpanel".to_string(),
            name: "Mixpanel Analytics".to_string(),
            category: CapabilityCategory::Telemetry,
            description: "Mixpanel analytics service".to_string(),
            pattern_type: PatternType::String,
            pattern: "mixpanel.com".to_string(),
            confidence: 0.95,
            severity: Severity::High,
            tags: vec!["mixpanel".to_string(), "analytics".to_string()],
        },
        Signature {
            id: "tel-amplitude".to_string(),
            name: "Amplitude Analytics".to_string(),
            category: CapabilityCategory::Telemetry,
            description: "Amplitude analytics service".to_string(),
            pattern_type: PatternType::String,
            pattern: "amplitude.com".to_string(),
            confidence: 0.95,
            severity: Severity::High,
            tags: vec!["amplitude".to_string(), "analytics".to_string()],
        },
    ]
}

fn storage_signatures() -> Vec<Signature> {
    vec![
        Signature {
            id: "stor-sqlite".to_string(),
            name: "SQLite Database".to_string(),
            category: CapabilityCategory::Storage,
            description: "SQLite embedded database".to_string(),
            pattern_type: PatternType::String,
            pattern: "SQLite format 3".to_string(),
            confidence: 0.95,
            severity: Severity::Medium,
            tags: vec!["sqlite".to_string(), "database".to_string()],
        },
        Signature {
            id: "stor-leveldb".to_string(),
            name: "LevelDB".to_string(),
            category: CapabilityCategory::Storage,
            description: "LevelDB key-value store".to_string(),
            pattern_type: PatternType::String,
            pattern: "leveldb".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["leveldb".to_string(), "kvstore".to_string()],
        },
        Signature {
            id: "stor-nvs".to_string(),
            name: "NVS Storage".to_string(),
            category: CapabilityCategory::Storage,
            description: "Non-volatile storage partition".to_string(),
            pattern_type: PatternType::String,
            pattern: "nvs_flash".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["nvs".to_string(), "flash".to_string()],
        },
        Signature {
            id: "stor-spiffs".to_string(),
            name: "SPIFFS Filesystem".to_string(),
            category: CapabilityCategory::Storage,
            description: "SPI Flash File System".to_string(),
            pattern_type: PatternType::String,
            pattern: "SPIFFS".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["spiffs".to_string(), "flash".to_string()],
        },
        Signature {
            id: "stor-littlefs".to_string(),
            name: "LittleFS".to_string(),
            category: CapabilityCategory::Storage,
            description: "Little File System for embedded".to_string(),
            pattern_type: PatternType::String,
            pattern: "littlefs".to_string(),
            confidence: 0.9,
            severity: Severity::Medium,
            tags: vec!["littlefs".to_string(), "embedded".to_string()],
        },
    ]
}

fn update_signatures() -> Vec<Signature> {
    vec![
        Signature {
            id: "upd-ota".to_string(),
            name: "OTA Update".to_string(),
            category: CapabilityCategory::Update,
            description: "Over-the-air update capability".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"(ota|OTA)[_-]?(update|upgrade|firmware)".to_string(),
            confidence: 0.9,
            severity: Severity::High,
            tags: vec!["ota".to_string(), "update".to_string()],
        },
        Signature {
            id: "upd-fwup".to_string(),
            name: "Firmware Update".to_string(),
            category: CapabilityCategory::Update,
            description: "Firmware update mechanism".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"firmware[_-]?(update|upgrade)".to_string(),
            confidence: 0.9,
            severity: Severity::High,
            tags: vec!["firmware".to_string(), "update".to_string()],
        },
        Signature {
            id: "upd-delta".to_string(),
            name: "Delta Update".to_string(),
            category: CapabilityCategory::Update,
            description: "Delta/differential update capability".to_string(),
            pattern_type: PatternType::String,
            pattern: "bsdiff".to_string(),
            confidence: 0.85,
            severity: Severity::Medium,
            tags: vec!["delta".to_string(), "bsdiff".to_string()],
        },
        Signature {
            id: "upd-rollback".to_string(),
            name: "Rollback Mechanism".to_string(),
            category: CapabilityCategory::Update,
            description: "Firmware rollback capability".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"(rollback|revert)[_-]?(firmware|update)".to_string(),
            confidence: 0.85,
            severity: Severity::Medium,
            tags: vec!["rollback".to_string(), "recovery".to_string()],
        },
        Signature {
            id: "upd-a-b-slot".to_string(),
            name: "A/B Partition Scheme".to_string(),
            category: CapabilityCategory::Update,
            description: "Dual partition update scheme".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"(slot[_-]?[ab]|partition[_-]?[ab])".to_string(),
            confidence: 0.85,
            severity: Severity::Medium,
            tags: vec!["ab".to_string(), "partition".to_string()],
        },
        Signature {
            id: "upd-swupdate".to_string(),
            name: "SWUpdate".to_string(),
            category: CapabilityCategory::Update,
            description: "SWUpdate Linux update framework".to_string(),
            pattern_type: PatternType::String,
            pattern: "swupdate".to_string(),
            confidence: 0.95,
            severity: Severity::High,
            tags: vec!["swupdate".to_string(), "linux".to_string()],
        },
    ]
}

fn identity_signatures() -> Vec<Signature> {
    vec![
        Signature {
            id: "id-uuid".to_string(),
            name: "UUID Pattern".to_string(),
            category: CapabilityCategory::Identity,
            description: "UUID identifier pattern".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}".to_string(),
            confidence: 0.8,
            severity: Severity::Medium,
            tags: vec!["uuid".to_string(), "identifier".to_string()],
        },
        Signature {
            id: "id-mac-addr".to_string(),
            name: "MAC Address Usage".to_string(),
            category: CapabilityCategory::Identity,
            description: "MAC address as identifier".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}".to_string(),
            confidence: 0.75,
            severity: Severity::Medium,
            tags: vec!["mac".to_string(), "hardware".to_string()],
        },
        Signature {
            id: "id-imei".to_string(),
            name: "IMEI Pattern".to_string(),
            category: CapabilityCategory::Identity,
            description: "IMEI mobile device identifier".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"imei|IMEI".to_string(),
            confidence: 0.9,
            severity: Severity::High,
            tags: vec!["imei".to_string(), "mobile".to_string()],
        },
        Signature {
            id: "id-serial".to_string(),
            name: "Serial Number Access".to_string(),
            category: CapabilityCategory::Identity,
            description: "Serial number identifier access".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"(serial[_-]?number|serialNumber|get[_-]?serial)".to_string(),
            confidence: 0.85,
            severity: Severity::Medium,
            tags: vec!["serial".to_string(), "identifier".to_string()],
        },
        Signature {
            id: "id-hwid".to_string(),
            name: "Hardware ID".to_string(),
            category: CapabilityCategory::Identity,
            description: "Hardware identifier access".to_string(),
            pattern_type: PatternType::Regex,
            pattern: r"(hardware[_-]?id|hwid|chip[_-]?id)".to_string(),
            confidence: 0.85,
            severity: Severity::Medium,
            tags: vec!["hwid".to_string(), "hardware".to_string()],
        },
    ]
}

fn crypto_signatures() -> Vec<Signature> {
    vec![
        Signature {
            id: "crypto-openssl".to_string(),
            name: "OpenSSL".to_string(),
            category: CapabilityCategory::Crypto,
            description: "OpenSSL cryptographic library".to_string(),
            pattern_type: PatternType::String,
            pattern: "OpenSSL".to_string(),
            confidence: 0.95,
            severity: Severity::Info,
            tags: vec!["openssl".to_string(), "tls".to_string()],
        },
        Signature {
            id: "crypto-mbedtls".to_string(),
            name: "mbedTLS".to_string(),
            category: CapabilityCategory::Crypto,
            description: "mbedTLS embedded crypto library".to_string(),
            pattern_type: PatternType::String,
            pattern: "mbedtls".to_string(),
            confidence: 0.95,
            severity: Severity::Info,
            tags: vec!["mbedtls".to_string(), "embedded".to_string()],
        },
        Signature {
            id: "crypto-wolfssl".to_string(),
            name: "wolfSSL".to_string(),
            category: CapabilityCategory::Crypto,
            description: "wolfSSL TLS library".to_string(),
            pattern_type: PatternType::String,
            pattern: "wolfSSL".to_string(),
            confidence: 0.95,
            severity: Severity::Info,
            tags: vec!["wolfssl".to_string(), "tls".to_string()],
        },
        Signature {
            id: "crypto-aes".to_string(),
            name: "AES Encryption".to_string(),
            category: CapabilityCategory::Crypto,
            description: "AES encryption capability".to_string(),
            pattern_type: PatternType::Symbol,
            pattern: "AES_encrypt".to_string(),
            confidence: 0.9,
            severity: Severity::Info,
            tags: vec!["aes".to_string(), "encryption".to_string()],
        },
        Signature {
            id: "crypto-rsa".to_string(),
            name: "RSA Crypto".to_string(),
            category: CapabilityCategory::Crypto,
            description: "RSA cryptographic operations".to_string(),
            pattern_type: PatternType::Symbol,
            pattern: "RSA_public_encrypt".to_string(),
            confidence: 0.9,
            severity: Severity::Info,
            tags: vec!["rsa".to_string(), "asymmetric".to_string()],
        },
        Signature {
            id: "crypto-sha256".to_string(),
            name: "SHA-256 Hash".to_string(),
            category: CapabilityCategory::Crypto,
            description: "SHA-256 hashing capability".to_string(),
            pattern_type: PatternType::Symbol,
            pattern: "SHA256_Update".to_string(),
            confidence: 0.9,
            severity: Severity::Info,
            tags: vec!["sha256".to_string(), "hash".to_string()],
        },
        Signature {
            id: "crypto-cert".to_string(),
            name: "X.509 Certificate".to_string(),
            category: CapabilityCategory::Crypto,
            description: "X.509 certificate handling".to_string(),
            pattern_type: PatternType::String,
            pattern: "-----BEGIN CERTIFICATE-----".to_string(),
            confidence: 0.95,
            severity: Severity::Medium,
            tags: vec!["x509".to_string(), "certificate".to_string()],
        },
        Signature {
            id: "crypto-privkey".to_string(),
            name: "Private Key".to_string(),
            category: CapabilityCategory::Crypto,
            description: "Private key material present".to_string(),
            pattern_type: PatternType::String,
            pattern: "-----BEGIN PRIVATE KEY-----".to_string(),
            confidence: 0.95,
            severity: Severity::Critical,
            tags: vec!["private".to_string(), "key".to_string()],
        },
    ]
}

/// Static default database instance
pub static DEFAULT_DATABASE: Lazy<SignatureDatabase> = Lazy::new(|| {
    SignatureDatabase::default_database().expect("Failed to create default signature database")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let db = SignatureDatabase::default_database().unwrap();
        assert!(!db.signatures().is_empty());
    }

    #[test]
    fn test_string_matching() {
        let db = SignatureDatabase::default_database().unwrap();
        let data = b"This firmware uses lwIP TCP/IP stack";
        let matches = db.scan(data, MatchContext::default());
        assert!(matches.iter().any(|m| m.signature_id == "net-lwip"));
    }

    #[test]
    fn test_regex_matching() {
        let db = SignatureDatabase::default_database().unwrap();
        let data = b"connecting to https://api.example.com/data";
        let matches = db.scan(data, MatchContext::default());
        assert!(matches.iter().any(|m| m.signature_id == "net-https-url"));
    }

    #[test]
    fn test_category_filtering() {
        let db = SignatureDatabase::default_database().unwrap();
        let net_sigs = db.signatures_by_category(CapabilityCategory::Networking);
        assert!(!net_sigs.is_empty());
        assert!(net_sigs.iter().all(|s| s.category == CapabilityCategory::Networking));
    }
}
