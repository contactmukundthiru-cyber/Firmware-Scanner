//! ClamAV integration for malware detection
//!
//! ClamAV is an open source antivirus engine for detecting trojans, viruses, malware.

use crate::{
    ExternalTool, Finding, FindingCategory, FindingSeverity,
    ToolConfig, ToolError, ToolResult, run_command,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// ClamAV scanner
pub struct ClamAV {
    config: ToolConfig,
    clamscan_executable: Option<PathBuf>,
    freshclam_executable: Option<PathBuf>,
}

impl ClamAV {
    pub fn new(config: ToolConfig) -> ToolResult<Self> {
        let clamscan_executable = config.tool_paths.get("clamscan")
            .cloned()
            .or_else(|| crate::get_command_path("clamscan"))
            .or_else(|| crate::get_command_path("clamdscan"));

        let freshclam_executable = config.tool_paths.get("freshclam")
            .cloned()
            .or_else(|| crate::get_command_path("freshclam"));

        Ok(Self {
            config,
            clamscan_executable,
            freshclam_executable,
        })
    }

    /// Scan a file for malware
    pub async fn scan(&self, file_path: &Path) -> ToolResult<ClamScanResult> {
        let exe = self.clamscan_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("clamscan".to_string()))?;

        let start = std::time::Instant::now();

        let (stdout, stderr, code) = run_command(
            exe.to_str().unwrap(),
            &[
                "--no-summary",
                "--infected",
                file_path.to_str().unwrap(),
            ],
            self.config.timeout_secs,
        ).await?;

        let mut detections = Vec::new();

        // Parse output for detections
        for line in stdout.lines() {
            if line.contains("FOUND") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let virus_name = parts[1].replace("FOUND", "").trim().to_string();
                    detections.push(ClamDetection {
                        file: parts[0].trim().to_string(),
                        malware_name: virus_name,
                    });
                }
            }
        }

        Ok(ClamScanResult {
            duration_ms: start.elapsed().as_millis() as u64,
            infected: !detections.is_empty(),
            detections,
            raw_output: stdout,
            errors: if stderr.is_empty() { Vec::new() } else { vec![stderr] },
        })
    }

    /// Scan a directory recursively
    pub async fn scan_directory(&self, dir_path: &Path) -> ToolResult<ClamScanResult> {
        let exe = self.clamscan_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("clamscan".to_string()))?;

        let start = std::time::Instant::now();

        let (stdout, stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &[
                "--no-summary",
                "--infected",
                "-r",  // Recursive
                dir_path.to_str().unwrap(),
            ],
            self.config.timeout_secs * 5, // More time for directories
        ).await?;

        let mut detections = Vec::new();

        for line in stdout.lines() {
            if line.contains("FOUND") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let virus_name = parts[1].replace("FOUND", "").trim().to_string();
                    detections.push(ClamDetection {
                        file: parts[0].trim().to_string(),
                        malware_name: virus_name,
                    });
                }
            }
        }

        Ok(ClamScanResult {
            duration_ms: start.elapsed().as_millis() as u64,
            infected: !detections.is_empty(),
            detections,
            raw_output: stdout,
            errors: if stderr.is_empty() { Vec::new() } else { vec![stderr] },
        })
    }

    /// Update virus database
    pub async fn update_database(&self) -> ToolResult<()> {
        let exe = self.freshclam_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("freshclam".to_string()))?;

        let (_stdout, stderr, code) = run_command(
            exe.to_str().unwrap(),
            &[],
            600, // 10 minutes for database update
        ).await?;

        if code != 0 {
            return Err(ToolError::ExecutionFailed(stderr));
        }

        Ok(())
    }

    /// Get database info
    pub async fn database_info(&self) -> ToolResult<DatabaseInfo> {
        let exe = self.clamscan_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("clamscan".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["--version"],
            10,
        ).await?;

        // Parse version info
        let version = stdout.lines().next().unwrap_or("").to_string();

        Ok(DatabaseInfo {
            version,
            signatures: 0, // Would need to parse from clamscan output
            last_update: None,
        })
    }

    /// Convert to generic findings
    pub fn to_findings(&self, result: &ClamScanResult) -> Vec<Finding> {
        result.detections.iter().map(|d| {
            Finding {
                category: FindingCategory::Malware,
                severity: FindingSeverity::Critical,
                title: format!("Malware detected: {}", d.malware_name),
                description: format!("ClamAV detected malware '{}' in file {}", d.malware_name, d.file),
                file_path: Some(d.file.clone()),
                offset: None,
                size: None,
                data: Some(serde_json::json!({
                    "malware_name": d.malware_name,
                    "file": d.file,
                })),
            }
        }).collect()
    }
}

#[async_trait]
impl ExternalTool for ClamAV {
    fn name(&self) -> &str {
        "clamav"
    }

    async fn is_available(&self) -> bool {
        self.clamscan_executable.is_some()
    }

    async fn version(&self) -> ToolResult<String> {
        let exe = self.clamscan_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("clamscan".to_string()))?;

        let (stdout, _, _) = run_command(
            exe.to_str().unwrap(),
            &["--version"],
            10,
        ).await?;

        Ok(stdout.lines().next().unwrap_or("unknown").to_string())
    }

    fn executable_path(&self) -> Option<&Path> {
        self.clamscan_executable.as_deref()
    }
}

/// ClamAV scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamScanResult {
    pub duration_ms: u64,
    pub infected: bool,
    pub detections: Vec<ClamDetection>,
    pub raw_output: String,
    pub errors: Vec<String>,
}

/// Individual malware detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamDetection {
    pub file: String,
    pub malware_name: String,
}

/// Database information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub version: String,
    pub signatures: u64,
    pub last_update: Option<String>,
}
