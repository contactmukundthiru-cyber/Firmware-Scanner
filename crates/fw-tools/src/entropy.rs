//! Entropy analysis for detecting encrypted or compressed sections
//!
//! High entropy regions often indicate encryption or compression.

use crate::{
    Finding, FindingCategory, FindingSeverity,
    ToolConfig, ToolResult,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Entropy analyzer (pure Rust, no external tool needed)
pub struct EntropyAnalyzer {
    config: ToolConfig,
    block_size: usize,
}

impl EntropyAnalyzer {
    pub fn new(config: ToolConfig) -> Self {
        Self {
            config,
            block_size: 256, // Default block size
        }
    }

    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size;
        self
    }

    /// Analyze entropy of a file
    pub async fn analyze(&self, file_path: &Path) -> ToolResult<EntropyAnalysis> {
        let start = std::time::Instant::now();
        let data = tokio::fs::read(file_path).await?;

        let overall_entropy = calculate_entropy(&data);
        let blocks = self.analyze_blocks(&data);

        // Detect high entropy regions (likely encrypted/compressed)
        let high_entropy_regions: Vec<_> = blocks.iter()
            .filter(|b| b.entropy > 7.5)
            .cloned()
            .collect();

        // Detect low entropy regions (likely padding or repeated data)
        let low_entropy_regions: Vec<_> = blocks.iter()
            .filter(|b| b.entropy < 1.0 && b.size > 100)
            .cloned()
            .collect();

        // Detect entropy boundaries (transitions)
        let boundaries = self.detect_boundaries(&blocks);

        Ok(EntropyAnalysis {
            duration_ms: start.elapsed().as_millis() as u64,
            file_size: data.len(),
            overall_entropy,
            block_size: self.block_size,
            blocks,
            high_entropy_regions,
            low_entropy_regions,
            boundaries,
        })
    }

    /// Analyze file in blocks
    fn analyze_blocks(&self, data: &[u8]) -> Vec<EntropyBlock> {
        let mut blocks = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + self.block_size).min(data.len());
            let block_data = &data[offset..end];
            let entropy = calculate_entropy(block_data);

            blocks.push(EntropyBlock {
                offset: offset as u64,
                size: (end - offset) as u64,
                entropy,
                classification: classify_entropy(entropy),
            });

            offset = end;
        }

        blocks
    }

    /// Detect significant entropy boundaries
    fn detect_boundaries(&self, blocks: &[EntropyBlock]) -> Vec<EntropyBoundary> {
        let mut boundaries = Vec::new();

        for i in 1..blocks.len() {
            let delta = (blocks[i].entropy - blocks[i - 1].entropy).abs();
            if delta > 2.0 {
                boundaries.push(EntropyBoundary {
                    offset: blocks[i].offset,
                    entropy_before: blocks[i - 1].entropy,
                    entropy_after: blocks[i].entropy,
                    delta,
                    likely_type: if blocks[i].entropy > blocks[i - 1].entropy {
                        "Start of encrypted/compressed section".to_string()
                    } else {
                        "End of encrypted/compressed section".to_string()
                    },
                });
            }
        }

        boundaries
    }

    /// Convert to generic findings
    pub fn to_findings(&self, analysis: &EntropyAnalysis) -> Vec<Finding> {
        let mut findings = Vec::new();

        if analysis.overall_entropy > 7.5 {
            findings.push(Finding {
                category: FindingCategory::Encryption,
                severity: FindingSeverity::Medium,
                title: "High overall entropy".to_string(),
                description: format!(
                    "File has high entropy ({:.2}), likely encrypted or highly compressed",
                    analysis.overall_entropy
                ),
                file_path: None,
                offset: None,
                size: Some(analysis.file_size as u64),
                data: Some(serde_json::json!({
                    "entropy": analysis.overall_entropy,
                })),
            });
        }

        for region in &analysis.high_entropy_regions {
            findings.push(Finding {
                category: FindingCategory::Encryption,
                severity: FindingSeverity::Low,
                title: format!("High entropy region at 0x{:X}", region.offset),
                description: format!(
                    "Region with entropy {:.2} detected, possibly encrypted/compressed",
                    region.entropy
                ),
                file_path: None,
                offset: Some(region.offset),
                size: Some(region.size),
                data: Some(serde_json::json!({
                    "entropy": region.entropy,
                    "classification": format!("{:?}", region.classification),
                })),
            });
        }

        for boundary in &analysis.boundaries {
            findings.push(Finding {
                category: FindingCategory::Metadata,
                severity: FindingSeverity::Info,
                title: format!("Entropy boundary at 0x{:X}", boundary.offset),
                description: boundary.likely_type.clone(),
                file_path: None,
                offset: Some(boundary.offset),
                size: None,
                data: Some(serde_json::json!({
                    "before": boundary.entropy_before,
                    "after": boundary.entropy_after,
                    "delta": boundary.delta,
                })),
            });
        }

        findings
    }
}

/// Calculate Shannon entropy of data
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Classify entropy level
fn classify_entropy(entropy: f64) -> EntropyClassification {
    if entropy < 1.0 {
        EntropyClassification::VeryLow
    } else if entropy < 3.0 {
        EntropyClassification::Low
    } else if entropy < 5.0 {
        EntropyClassification::Medium
    } else if entropy < 7.0 {
        EntropyClassification::High
    } else if entropy < 7.9 {
        EntropyClassification::VeryHigh
    } else {
        EntropyClassification::Random
    }
}

/// Entropy analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    pub duration_ms: u64,
    pub file_size: usize,
    pub overall_entropy: f64,
    pub block_size: usize,
    pub blocks: Vec<EntropyBlock>,
    pub high_entropy_regions: Vec<EntropyBlock>,
    pub low_entropy_regions: Vec<EntropyBlock>,
    pub boundaries: Vec<EntropyBoundary>,
}

/// Entropy of a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyBlock {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub classification: EntropyClassification,
}

/// Entropy classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum EntropyClassification {
    VeryLow,   // < 1.0 - repeated or null data
    Low,       // 1.0 - 3.0 - text/code
    Medium,    // 3.0 - 5.0 - mixed content
    High,      // 5.0 - 7.0 - possibly compressed
    VeryHigh,  // 7.0 - 7.9 - likely compressed/encrypted
    Random,    // > 7.9 - encrypted or random
}

/// Entropy boundary (transition point)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyBoundary {
    pub offset: u64,
    pub entropy_before: f64,
    pub entropy_after: f64,
    pub delta: f64,
    pub likely_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // All zeros should have 0 entropy
        let zeros = vec![0u8; 1000];
        assert_eq!(calculate_entropy(&zeros), 0.0);

        // All same value
        let same = vec![42u8; 1000];
        assert_eq!(calculate_entropy(&same), 0.0);

        // Two values equally distributed
        let two: Vec<u8> = (0..1000).map(|i| (i % 2) as u8).collect();
        let e = calculate_entropy(&two);
        assert!((e - 1.0).abs() < 0.01); // Should be ~1.0 bit

        // Random-ish data should have high entropy
        let random: Vec<u8> = (0..256).map(|i| i as u8).cycle().take(1000).collect();
        let e = calculate_entropy(&random);
        assert!(e > 7.0); // Should be close to 8.0
    }
}
