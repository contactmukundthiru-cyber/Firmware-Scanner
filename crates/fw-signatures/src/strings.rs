//! String pattern matching for capability detection

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// String signature category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringCategory {
    /// URLs and endpoints
    Endpoint,
    /// API keys, tokens
    Credential,
    /// Error messages
    ErrorMessage,
    /// Version strings
    Version,
    /// Configuration
    Config,
    /// Debug/logging
    Debug,
    /// Network protocol
    Protocol,
    /// File path
    FilePath,
    /// Command
    Command,
}

/// String signature for capability detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringSignature {
    pub id: String,
    pub category: StringCategory,
    pub pattern: String,
    pub is_regex: bool,
    pub case_sensitive: bool,
    pub description: String,
    pub severity: StringSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StringSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// String match result
#[derive(Debug, Clone)]
pub struct StringMatch {
    pub signature_id: String,
    pub category: StringCategory,
    pub offset: usize,
    pub matched_string: String,
    pub severity: StringSeverity,
}

/// High-performance string scanner
pub struct StringScanner {
    literal_signatures: Vec<StringSignature>,
    regex_signatures: Vec<StringSignature>,
    literal_matcher: AhoCorasick,
    regex_matcher: Option<RegexSet>,
}

impl StringScanner {
    /// Create a new string scanner
    pub fn new(signatures: Vec<StringSignature>) -> Self {
        let (literal_sigs, regex_sigs): (Vec<_>, Vec<_>) = signatures
            .into_iter()
            .partition(|s| !s.is_regex);

        // Build Aho-Corasick for literal patterns
        let literal_patterns: Vec<&str> = literal_sigs
            .iter()
            .map(|s| s.pattern.as_str())
            .collect();

        let literal_matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&literal_patterns)
            .unwrap();

        // Build regex set if there are regex patterns
        let regex_matcher = if !regex_sigs.is_empty() {
            let regex_patterns: Vec<&str> = regex_sigs
                .iter()
                .map(|s| s.pattern.as_str())
                .collect();
            RegexSet::new(&regex_patterns).ok()
        } else {
            None
        };

        Self {
            literal_signatures: literal_sigs,
            regex_signatures: regex_sigs,
            literal_matcher,
            regex_matcher,
        }
    }

    /// Create scanner with default signatures
    pub fn default_scanner() -> Self {
        Self::new(default_string_signatures())
    }

    /// Scan binary data for string matches
    pub fn scan(&self, data: &[u8]) -> Vec<StringMatch> {
        let mut matches = Vec::new();

        // Convert to string for scanning
        let text = String::from_utf8_lossy(data);

        // Literal matching with Aho-Corasick
        for mat in self.literal_matcher.find_iter(text.as_ref()) {
            let sig = &self.literal_signatures[mat.pattern().as_usize()];
            let matched = &text[mat.start()..mat.end()];

            matches.push(StringMatch {
                signature_id: sig.id.clone(),
                category: sig.category,
                offset: mat.start(),
                matched_string: matched.to_string(),
                severity: sig.severity,
            });
        }

        // Regex matching
        if let Some(ref regex_set) = self.regex_matcher {
            for idx in regex_set.matches(&text) {
                let sig = &self.regex_signatures[idx];
                // For regex matches, we need to use the individual regex to get position
                if let Ok(re) = regex::Regex::new(&sig.pattern) {
                    for mat in re.find_iter(&text) {
                        matches.push(StringMatch {
                            signature_id: sig.id.clone(),
                            category: sig.category,
                            offset: mat.start(),
                            matched_string: mat.as_str().to_string(),
                            severity: sig.severity,
                        });
                    }
                }
            }
        }

        matches
    }

    /// Extract all printable strings from binary
    pub fn extract_strings(&self, data: &[u8], min_length: usize) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let mut current = Vec::new();
        let mut start_offset = 0;

        for (i, &byte) in data.iter().enumerate() {
            if byte >= 0x20 && byte < 0x7F {
                if current.is_empty() {
                    start_offset = i;
                }
                current.push(byte);
            } else if byte == 0 && current.len() >= min_length {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(ExtractedString {
                        value: s,
                        offset: start_offset,
                        length: current.len(),
                        encoding: StringEncoding::Ascii,
                    });
                }
                current.clear();
            } else {
                current.clear();
            }
        }

        // Check for trailing string
        if current.len() >= min_length {
            if let Ok(s) = String::from_utf8(current.clone()) {
                strings.push(ExtractedString {
                    value: s,
                    offset: start_offset,
                    length: current.len(),
                    encoding: StringEncoding::Ascii,
                });
            }
        }

        strings
    }

    /// Extract UTF-16 strings (common in PE binaries)
    pub fn extract_wide_strings(&self, data: &[u8], min_length: usize) -> Vec<ExtractedString> {
        let mut strings = Vec::new();

        if data.len() < 2 {
            return strings;
        }

        let mut current = Vec::new();
        let mut start_offset = 0;
        let mut i = 0;

        while i + 1 < data.len() {
            let wchar = u16::from_le_bytes([data[i], data[i + 1]]);

            if wchar >= 0x20 && wchar < 0x7F {
                if current.is_empty() {
                    start_offset = i;
                }
                current.push(wchar as u8);
                i += 2;
            } else if wchar == 0 && current.len() >= min_length {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(ExtractedString {
                        value: s,
                        offset: start_offset,
                        length: current.len() * 2,
                        encoding: StringEncoding::Utf16Le,
                    });
                }
                current.clear();
                i += 2;
            } else {
                current.clear();
                i += 2;
            }
        }

        strings
    }
}

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub length: usize,
    pub encoding: StringEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// Default string signatures for firmware analysis
pub fn default_string_signatures() -> Vec<StringSignature> {
    vec![
        // Endpoints
        StringSignature {
            id: "endpoint-http".to_string(),
            category: StringCategory::Endpoint,
            pattern: r"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}".to_string(),
            is_regex: true,
            case_sensitive: false,
            description: "HTTP/HTTPS URL endpoint".to_string(),
            severity: StringSeverity::High,
        },
        StringSignature {
            id: "endpoint-api".to_string(),
            category: StringCategory::Endpoint,
            pattern: "/api/".to_string(),
            is_regex: false,
            case_sensitive: false,
            description: "API endpoint path".to_string(),
            severity: StringSeverity::Medium,
        },
        StringSignature {
            id: "endpoint-mqtt".to_string(),
            category: StringCategory::Endpoint,
            pattern: r"mqtt://[a-zA-Z0-9\-\.]+".to_string(),
            is_regex: true,
            case_sensitive: false,
            description: "MQTT broker endpoint".to_string(),
            severity: StringSeverity::High,
        },

        // Credentials
        StringSignature {
            id: "cred-api-key".to_string(),
            category: StringCategory::Credential,
            pattern: r#"(api[_-]?key|apikey)\s*[:=]\s*['"]?[a-zA-Z0-9]{16,}"#.to_string(),
            is_regex: true,
            case_sensitive: false,
            description: "Hardcoded API key".to_string(),
            severity: StringSeverity::Critical,
        },
        StringSignature {
            id: "cred-password".to_string(),
            category: StringCategory::Credential,
            pattern: r#"(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}"#.to_string(),
            is_regex: true,
            case_sensitive: false,
            description: "Hardcoded password".to_string(),
            severity: StringSeverity::Critical,
        },
        StringSignature {
            id: "cred-private-key".to_string(),
            category: StringCategory::Credential,
            pattern: "-----BEGIN PRIVATE KEY-----".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Embedded private key".to_string(),
            severity: StringSeverity::Critical,
        },
        StringSignature {
            id: "cred-rsa-key".to_string(),
            category: StringCategory::Credential,
            pattern: "-----BEGIN RSA PRIVATE KEY-----".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Embedded RSA private key".to_string(),
            severity: StringSeverity::Critical,
        },

        // Debug
        StringSignature {
            id: "debug-gdb".to_string(),
            category: StringCategory::Debug,
            pattern: "gdbserver".to_string(),
            is_regex: false,
            case_sensitive: false,
            description: "GDB server for remote debugging".to_string(),
            severity: StringSeverity::Medium,
        },
        StringSignature {
            id: "debug-strace".to_string(),
            category: StringCategory::Debug,
            pattern: "strace".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "System call tracer".to_string(),
            severity: StringSeverity::Medium,
        },
        StringSignature {
            id: "debug-printf".to_string(),
            category: StringCategory::Debug,
            pattern: "DEBUG:".to_string(),
            is_regex: false,
            case_sensitive: false,
            description: "Debug print statement".to_string(),
            severity: StringSeverity::Low,
        },

        // Version strings
        StringSignature {
            id: "version-linux".to_string(),
            category: StringCategory::Version,
            pattern: "Linux version".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Linux kernel version".to_string(),
            severity: StringSeverity::Info,
        },
        StringSignature {
            id: "version-gcc".to_string(),
            category: StringCategory::Version,
            pattern: "GCC:".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "GCC compiler version".to_string(),
            severity: StringSeverity::Info,
        },
        StringSignature {
            id: "version-busybox".to_string(),
            category: StringCategory::Version,
            pattern: "BusyBox v".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "BusyBox version".to_string(),
            severity: StringSeverity::Info,
        },

        // Commands
        StringSignature {
            id: "cmd-shell".to_string(),
            category: StringCategory::Command,
            pattern: "/bin/sh".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Shell path".to_string(),
            severity: StringSeverity::Low,
        },
        StringSignature {
            id: "cmd-bash".to_string(),
            category: StringCategory::Command,
            pattern: "/bin/bash".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Bash shell path".to_string(),
            severity: StringSeverity::Low,
        },
        StringSignature {
            id: "cmd-telnetd".to_string(),
            category: StringCategory::Command,
            pattern: "telnetd".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Telnet daemon".to_string(),
            severity: StringSeverity::High,
        },
        StringSignature {
            id: "cmd-dropbear".to_string(),
            category: StringCategory::Command,
            pattern: "dropbear".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Dropbear SSH server".to_string(),
            severity: StringSeverity::Medium,
        },

        // File paths
        StringSignature {
            id: "path-etc-passwd".to_string(),
            category: StringCategory::FilePath,
            pattern: "/etc/passwd".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Password file access".to_string(),
            severity: StringSeverity::Medium,
        },
        StringSignature {
            id: "path-etc-shadow".to_string(),
            category: StringCategory::FilePath,
            pattern: "/etc/shadow".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Shadow file access".to_string(),
            severity: StringSeverity::High,
        },
        StringSignature {
            id: "path-tmp".to_string(),
            category: StringCategory::FilePath,
            pattern: "/tmp/".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "Temporary directory".to_string(),
            severity: StringSeverity::Low,
        },

        // Protocols
        StringSignature {
            id: "proto-http11".to_string(),
            category: StringCategory::Protocol,
            pattern: "HTTP/1.1".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "HTTP protocol".to_string(),
            severity: StringSeverity::Info,
        },
        StringSignature {
            id: "proto-tls".to_string(),
            category: StringCategory::Protocol,
            pattern: "TLSv1".to_string(),
            is_regex: false,
            case_sensitive: true,
            description: "TLS protocol".to_string(),
            severity: StringSeverity::Info,
        },
    ]
}

/// Interesting strings filter
pub fn filter_interesting_strings(strings: &[ExtractedString]) -> Vec<&ExtractedString> {
    strings
        .iter()
        .filter(|s| {
            let v = &s.value;

            // Filter out common uninteresting patterns
            if v.len() < 4 {
                return false;
            }

            // URLs
            if v.contains("http://") || v.contains("https://") {
                return true;
            }

            // File paths
            if v.starts_with('/') && v.contains('/') {
                return true;
            }

            // IP addresses (rough check)
            if v.chars().filter(|&c| c == '.').count() == 3
                && v.chars().all(|c| c.is_numeric() || c == '.')
            {
                return true;
            }

            // Email addresses
            if v.contains('@') && v.contains('.') {
                return true;
            }

            // Environment variables
            if v.contains('=') && v.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                return true;
            }

            // Version strings
            if v.contains("version") || v.contains("Version") {
                return true;
            }

            // Error messages
            if v.contains("error") || v.contains("Error") || v.contains("failed") {
                return true;
            }

            // Function names (likely)
            if v.ends_with("()") || v.contains("_init") || v.contains("_exit") {
                return true;
            }

            false
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_extraction() {
        let scanner = StringScanner::default_scanner();
        let data = b"Hello World\0https://example.com\0foobar";
        let strings = scanner.extract_strings(data, 4);

        assert!(strings.iter().any(|s| s.value == "Hello World"));
        assert!(strings.iter().any(|s| s.value == "https://example.com"));
    }

    #[test]
    fn test_string_scanning() {
        let scanner = StringScanner::default_scanner();
        let data = b"connecting to https://api.example.com/api/v1/data";
        let matches = scanner.scan(data);

        // Should match URL and /api/ patterns
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_credential_detection() {
        let scanner = StringScanner::default_scanner();
        let data = b"api_key = 'abcdef1234567890abcdef'";
        let matches = scanner.scan(data);

        assert!(matches.iter().any(|m| m.category == StringCategory::Credential));
    }
}
