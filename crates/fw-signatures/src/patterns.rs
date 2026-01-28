//! Binary patterns for capability detection

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};

/// Binary pattern with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub bytes: Vec<u8>,
    pub mask: Option<Vec<u8>>,
    pub alignment: Option<usize>,
    pub min_occurrences: usize,
    pub category: PatternCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternCategory {
    NetworkStack,
    CryptoLibrary,
    CompressionLib,
    Bootloader,
    Kernel,
    FileSystem,
    UpdateMechanism,
    DebugInterface,
    HardwareAccess,
}

impl BinaryPattern {
    /// Search for pattern in data
    pub fn find_all(&self, data: &[u8]) -> Vec<usize> {
        let mut matches = Vec::new();
        let pattern_len = self.bytes.len();

        if pattern_len == 0 || data.len() < pattern_len {
            return matches;
        }

        let step = self.alignment.unwrap_or(1);

        for offset in (0..=data.len() - pattern_len).step_by(step) {
            if self.matches_at(data, offset) {
                matches.push(offset);
            }
        }

        matches
    }

    /// Check if pattern matches at specific offset
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.bytes.len() > data.len() {
            return false;
        }

        let slice = &data[offset..offset + self.bytes.len()];

        match &self.mask {
            Some(mask) => {
                for i in 0..self.bytes.len() {
                    if (slice[i] & mask[i]) != (self.bytes[i] & mask[i]) {
                        return false;
                    }
                }
                true
            }
            None => slice == self.bytes.as_slice(),
        }
    }
}

/// Network stack detection patterns
pub fn network_patterns() -> Vec<BinaryPattern> {
    vec![
        BinaryPattern {
            id: "lwip-init".to_string(),
            name: "lwIP Initialization".to_string(),
            description: "lwIP TCP/IP stack initialization pattern".to_string(),
            bytes: b"lwip_init".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::NetworkStack,
        },
        BinaryPattern {
            id: "freertos-tcp".to_string(),
            name: "FreeRTOS+TCP".to_string(),
            description: "FreeRTOS+TCP network stack".to_string(),
            bytes: b"FreeRTOS_IPInit".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::NetworkStack,
        },
        BinaryPattern {
            id: "uip-stack".to_string(),
            name: "uIP Stack".to_string(),
            description: "uIP embedded TCP/IP stack".to_string(),
            bytes: b"uip_init".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::NetworkStack,
        },
        BinaryPattern {
            id: "netconn-api".to_string(),
            name: "Netconn API".to_string(),
            description: "lwIP netconn sequential API".to_string(),
            bytes: b"netconn_new".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::NetworkStack,
        },
    ]
}

/// Crypto library patterns
pub fn crypto_patterns() -> Vec<BinaryPattern> {
    vec![
        BinaryPattern {
            id: "openssl-version".to_string(),
            name: "OpenSSL Version".to_string(),
            description: "OpenSSL version string".to_string(),
            bytes: b"OpenSSL ".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::CryptoLibrary,
        },
        BinaryPattern {
            id: "mbedtls-version".to_string(),
            name: "mbedTLS Version".to_string(),
            description: "mbedTLS version string".to_string(),
            bytes: b"mbed TLS".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::CryptoLibrary,
        },
        BinaryPattern {
            id: "wolfssl-version".to_string(),
            name: "wolfSSL Version".to_string(),
            description: "wolfSSL version string".to_string(),
            bytes: b"wolfSSL".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::CryptoLibrary,
        },
        BinaryPattern {
            id: "bearssl".to_string(),
            name: "BearSSL".to_string(),
            description: "BearSSL TLS library".to_string(),
            bytes: b"BearSSL".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::CryptoLibrary,
        },
        // AES S-box (first 16 bytes) - indicates AES implementation
        BinaryPattern {
            id: "aes-sbox".to_string(),
            name: "AES S-Box".to_string(),
            description: "AES substitution box lookup table".to_string(),
            bytes: vec![0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                       0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
            mask: None,
            alignment: Some(16),
            min_occurrences: 1,
            category: PatternCategory::CryptoLibrary,
        },
    ]
}

/// Bootloader patterns
pub fn bootloader_patterns() -> Vec<BinaryPattern> {
    vec![
        BinaryPattern {
            id: "uboot-version".to_string(),
            name: "U-Boot Version".to_string(),
            description: "U-Boot bootloader version".to_string(),
            bytes: b"U-Boot ".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::Bootloader,
        },
        BinaryPattern {
            id: "barebox".to_string(),
            name: "Barebox".to_string(),
            description: "Barebox bootloader".to_string(),
            bytes: b"barebox".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::Bootloader,
        },
        BinaryPattern {
            id: "grub".to_string(),
            name: "GRUB".to_string(),
            description: "GNU GRUB bootloader".to_string(),
            bytes: b"GRUB".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::Bootloader,
        },
        BinaryPattern {
            id: "coreboot".to_string(),
            name: "coreboot".to_string(),
            description: "coreboot firmware".to_string(),
            bytes: b"coreboot".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::Bootloader,
        },
    ]
}

/// Debug interface patterns
pub fn debug_patterns() -> Vec<BinaryPattern> {
    vec![
        BinaryPattern {
            id: "gdb-stub".to_string(),
            name: "GDB Stub".to_string(),
            description: "GDB remote debugging stub".to_string(),
            bytes: b"$qSupported".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::DebugInterface,
        },
        BinaryPattern {
            id: "jtag-tap".to_string(),
            name: "JTAG TAP".to_string(),
            description: "JTAG Test Access Port".to_string(),
            bytes: b"JTAG".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::DebugInterface,
        },
        BinaryPattern {
            id: "uart-console".to_string(),
            name: "UART Console".to_string(),
            description: "Serial console interface".to_string(),
            bytes: b"console=ttyS".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::DebugInterface,
        },
    ]
}

/// Multi-pattern scanner
pub struct PatternScanner {
    patterns: Vec<BinaryPattern>,
    aho_corasick: AhoCorasick,
    pattern_indices: Vec<usize>,
}

impl PatternScanner {
    pub fn new(patterns: Vec<BinaryPattern>) -> Self {
        let byte_patterns: Vec<&[u8]> = patterns
            .iter()
            .filter(|p| p.mask.is_none())
            .map(|p| p.bytes.as_slice())
            .collect();

        let pattern_indices: Vec<usize> = patterns
            .iter()
            .enumerate()
            .filter(|(_, p)| p.mask.is_none())
            .map(|(i, _)| i)
            .collect();

        let aho_corasick = AhoCorasick::new(&byte_patterns).unwrap();

        Self {
            patterns,
            aho_corasick,
            pattern_indices,
        }
    }

    /// Default scanner with all patterns
    pub fn default_scanner() -> Self {
        let mut all_patterns = Vec::new();
        all_patterns.extend(network_patterns());
        all_patterns.extend(crypto_patterns());
        all_patterns.extend(bootloader_patterns());
        all_patterns.extend(debug_patterns());
        Self::new(all_patterns)
    }

    /// Scan data for all patterns
    pub fn scan(&self, data: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Use Aho-Corasick for patterns without masks
        for mat in self.aho_corasick.find_iter(data) {
            let pattern_idx = self.pattern_indices[mat.pattern().as_usize()];
            let pattern = &self.patterns[pattern_idx];

            matches.push(PatternMatch {
                pattern_id: pattern.id.clone(),
                pattern_name: pattern.name.clone(),
                offset: mat.start(),
                length: mat.end() - mat.start(),
                category: pattern.category,
            });
        }

        // Handle patterns with masks separately
        for (idx, pattern) in self.patterns.iter().enumerate() {
            if pattern.mask.is_some() {
                for offset in pattern.find_all(data) {
                    matches.push(PatternMatch {
                        pattern_id: pattern.id.clone(),
                        pattern_name: pattern.name.clone(),
                        offset,
                        length: pattern.bytes.len(),
                        category: pattern.category,
                    });
                }
            }
        }

        matches
    }

    /// Get patterns by category
    pub fn patterns_by_category(&self, category: PatternCategory) -> Vec<&BinaryPattern> {
        self.patterns
            .iter()
            .filter(|p| p.category == category)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_id: String,
    pub pattern_name: String,
    pub offset: usize,
    pub length: usize,
    pub category: PatternCategory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let pattern = BinaryPattern {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: "Test pattern".to_string(),
            bytes: b"test".to_vec(),
            mask: None,
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::NetworkStack,
        };

        let data = b"this is a test string with test";
        let matches = pattern.find_all(data);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], 10);
        assert_eq!(matches[1], 27);
    }

    #[test]
    fn test_pattern_scanner() {
        let scanner = PatternScanner::default_scanner();
        let data = b"U-Boot 2020.04 with lwIP support and OpenSSL crypto";
        let matches = scanner.scan(data);

        assert!(matches.iter().any(|m| m.pattern_name.contains("U-Boot")));
        assert!(matches.iter().any(|m| m.pattern_name.contains("OpenSSL")));
    }

    #[test]
    fn test_masked_pattern() {
        let pattern = BinaryPattern {
            id: "masked".to_string(),
            name: "Masked Pattern".to_string(),
            description: "Pattern with mask".to_string(),
            bytes: vec![0xAB, 0xCD, 0xEF],
            mask: Some(vec![0xFF, 0xF0, 0xFF]),
            alignment: None,
            min_occurrences: 1,
            category: PatternCategory::NetworkStack,
        };

        assert!(pattern.matches_at(&[0xAB, 0xC0, 0xEF], 0)); // Matches with mask
        assert!(pattern.matches_at(&[0xAB, 0xCF, 0xEF], 0)); // Also matches
        assert!(!pattern.matches_at(&[0xAB, 0xDD, 0xEF], 0)); // Doesn't match
    }
}
