//! Binwalk integration for firmware extraction and analysis
//!
//! Binwalk is a tool for searching binary images for embedded files and executable code.

use crate::{
    AnalysisResult, ExternalTool, Finding, FindingCategory, FindingSeverity,
    ToolConfig, ToolError, ToolResult, command_exists, run_command,
};
use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Binwalk tool wrapper
pub struct Binwalk {
    config: ToolConfig,
    executable: Option<PathBuf>,
}

impl Binwalk {
    pub fn new(config: ToolConfig) -> ToolResult<Self> {
        let executable = config.tool_paths.get("binwalk")
            .cloned()
            .or_else(|| crate::get_command_path("binwalk"));

        Ok(Self { config, executable })
    }

    /// Scan a file for embedded files/filesystems
    pub async fn scan(&self, file_path: &Path) -> ToolResult<BinwalkScanResult> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("binwalk".to_string()))?;

        let start = std::time::Instant::now();

        let (stdout, stderr, code) = run_command(
            exe.to_str().unwrap(),
            &["-B", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        if code != 0 && !stderr.is_empty() {
            tracing::warn!("Binwalk stderr: {}", stderr);
        }

        let signatures = parse_binwalk_output(&stdout);

        Ok(BinwalkScanResult {
            duration_ms: start.elapsed().as_millis() as u64,
            signatures,
            raw_output: stdout,
        })
    }

    /// Extract embedded files from firmware
    pub async fn extract(&self, file_path: &Path, output_dir: &Path) -> ToolResult<BinwalkExtractResult> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("binwalk".to_string()))?;

        tokio::fs::create_dir_all(output_dir).await?;

        let start = std::time::Instant::now();

        let (stdout, stderr, code) = run_command(
            exe.to_str().unwrap(),
            &[
                "-e",                              // Extract
                "-M",                              // Recursively scan extracted files
                "-d", "5",                         // Max recursion depth
                "-C", output_dir.to_str().unwrap(), // Output directory
                file_path.to_str().unwrap(),
            ],
            self.config.timeout_secs,
        ).await?;

        // Count extracted files
        let mut extracted_files = Vec::new();
        if output_dir.exists() {
            for entry in walkdir::WalkDir::new(output_dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                extracted_files.push(entry.path().to_path_buf());
            }
        }

        Ok(BinwalkExtractResult {
            duration_ms: start.elapsed().as_millis() as u64,
            output_dir: output_dir.to_path_buf(),
            extracted_files,
            raw_output: stdout,
        })
    }

    /// Perform entropy analysis
    pub async fn entropy(&self, file_path: &Path) -> ToolResult<EntropyResult> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("binwalk".to_string()))?;

        let start = std::time::Instant::now();

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-E", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let regions = parse_entropy_output(&stdout);

        Ok(EntropyResult {
            duration_ms: start.elapsed().as_millis() as u64,
            high_entropy_regions: regions.iter().filter(|r| r.entropy > 0.9).count(),
            regions,
            raw_output: stdout,
        })
    }

    /// Convert scan result to generic findings
    pub fn to_findings(&self, scan: &BinwalkScanResult) -> Vec<Finding> {
        scan.signatures.iter().map(|sig| {
            let category = match sig.signature_type.to_lowercase().as_str() {
                s if s.contains("squashfs") => FindingCategory::FileSystem,
                s if s.contains("cramfs") => FindingCategory::FileSystem,
                s if s.contains("jffs") => FindingCategory::FileSystem,
                s if s.contains("ext") => FindingCategory::FileSystem,
                s if s.contains("ubi") => FindingCategory::FileSystem,
                s if s.contains("gzip") => FindingCategory::Compression,
                s if s.contains("lzma") => FindingCategory::Compression,
                s if s.contains("xz") => FindingCategory::Compression,
                s if s.contains("bzip") => FindingCategory::Compression,
                s if s.contains("zstd") => FindingCategory::Compression,
                s if s.contains("zip") => FindingCategory::Compression,
                s if s.contains("elf") => FindingCategory::Executable,
                s if s.contains("arm") => FindingCategory::Executable,
                s if s.contains("mips") => FindingCategory::Executable,
                s if s.contains("x86") => FindingCategory::Executable,
                s if s.contains("certificate") => FindingCategory::Certificate,
                s if s.contains("private key") => FindingCategory::Credentials,
                s if s.contains("aes") => FindingCategory::Encryption,
                s if s.contains("encrypt") => FindingCategory::Encryption,
                _ => FindingCategory::Unknown,
            };

            let severity = match category {
                FindingCategory::Credentials => FindingSeverity::Critical,
                FindingCategory::Encryption => FindingSeverity::Medium,
                _ => FindingSeverity::Info,
            };

            Finding {
                category,
                severity,
                title: sig.signature_type.clone(),
                description: sig.description.clone(),
                file_path: None,
                offset: Some(sig.offset),
                size: None,
                data: Some(serde_json::json!({
                    "signature": sig.signature_type,
                    "offset_hex": format!("0x{:X}", sig.offset),
                })),
            }
        }).collect()
    }
}

#[async_trait]
impl ExternalTool for Binwalk {
    fn name(&self) -> &str {
        "binwalk"
    }

    async fn is_available(&self) -> bool {
        self.executable.is_some() || command_exists("binwalk")
    }

    async fn version(&self) -> ToolResult<String> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("binwalk".to_string()))?;

        let (stdout, _, _) = run_command(
            exe.to_str().unwrap(),
            &["--help"],
            10,
        ).await?;

        // Parse version from help output
        let version = stdout.lines()
            .next()
            .unwrap_or("unknown")
            .to_string();

        Ok(version)
    }

    fn executable_path(&self) -> Option<&Path> {
        self.executable.as_deref()
    }
}

/// Binwalk scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinwalkScanResult {
    pub duration_ms: u64,
    pub signatures: Vec<BinwalkSignature>,
    pub raw_output: String,
}

/// Individual signature match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinwalkSignature {
    pub offset: u64,
    pub signature_type: String,
    pub description: String,
}

/// Binwalk extraction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinwalkExtractResult {
    pub duration_ms: u64,
    pub output_dir: PathBuf,
    pub extracted_files: Vec<PathBuf>,
    pub raw_output: String,
}

/// Entropy analysis region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyRegion {
    pub offset: u64,
    pub entropy: f64,
}

/// Entropy analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyResult {
    pub duration_ms: u64,
    pub high_entropy_regions: usize,
    pub regions: Vec<EntropyRegion>,
    pub raw_output: String,
}

/// Parse binwalk output into signatures
fn parse_binwalk_output(output: &str) -> Vec<BinwalkSignature> {
    let mut signatures = Vec::new();

    // Binwalk output format:
    // DECIMAL       HEXADECIMAL     DESCRIPTION
    // 0             0x0             ELF, 32-bit LSB executable, ARM, version 1
    let re = Regex::new(r"(\d+)\s+0x[0-9A-Fa-f]+\s+(.+)").unwrap();

    for line in output.lines() {
        if let Some(caps) = re.captures(line) {
            if let (Some(offset_str), Some(desc)) = (caps.get(1), caps.get(2)) {
                if let Ok(offset) = offset_str.as_str().parse::<u64>() {
                    let description = desc.as_str().trim().to_string();
                    let signature_type = description.split(',')
                        .next()
                        .unwrap_or(&description)
                        .trim()
                        .to_string();

                    signatures.push(BinwalkSignature {
                        offset,
                        signature_type,
                        description,
                    });
                }
            }
        }
    }

    signatures
}

/// Parse entropy output
fn parse_entropy_output(output: &str) -> Vec<EntropyRegion> {
    let mut regions = Vec::new();

    // Simplified entropy parsing - actual format varies
    let re = Regex::new(r"(\d+)\s+([\d.]+)").unwrap();

    for line in output.lines() {
        if let Some(caps) = re.captures(line) {
            if let (Some(offset_str), Some(entropy_str)) = (caps.get(1), caps.get(2)) {
                if let (Ok(offset), Ok(entropy)) = (
                    offset_str.as_str().parse::<u64>(),
                    entropy_str.as_str().parse::<f64>()
                ) {
                    regions.push(EntropyRegion { offset, entropy });
                }
            }
        }
    }

    regions
}
