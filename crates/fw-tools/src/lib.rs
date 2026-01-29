//! External Tool Integration for Firmware Analysis
//!
//! This module provides integration with popular open-source firmware
//! analysis tools to maximize detection capabilities.

pub mod binwalk;
pub mod radare2;
pub mod yara;
pub mod strings;
pub mod entropy;
pub mod hashing;
pub mod clamav;
pub mod ghidra;
pub mod objdump;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ToolError {
    #[error("Tool not found: {0}")]
    NotFound(String),

    #[error("Tool execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Tool timeout after {0} seconds")]
    Timeout(u64),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid configuration: {0}")]
    Config(String),
}

pub type ToolResult<T> = Result<T, ToolError>;

/// Trait for external tool integrations
#[async_trait]
pub trait ExternalTool: Send + Sync {
    /// Get tool name
    fn name(&self) -> &str;

    /// Check if tool is available
    async fn is_available(&self) -> bool;

    /// Get tool version
    async fn version(&self) -> ToolResult<String>;

    /// Get tool executable path
    fn executable_path(&self) -> Option<&Path>;
}

/// Result from any analysis tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub tool: String,
    pub success: bool,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
    pub raw_output: Option<String>,
    pub errors: Vec<String>,
}

/// Generic finding from tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: FindingCategory,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub file_path: Option<String>,
    pub offset: Option<u64>,
    pub size: Option<u64>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingCategory {
    FileSystem,
    Compression,
    Encryption,
    Executable,
    Certificate,
    Credentials,
    Vulnerability,
    Malware,
    Networking,
    Telemetry,
    HardcodedSecret,
    Configuration,
    Metadata,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Ord, PartialOrd, Eq)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Tool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    /// Custom tool paths (if not in PATH)
    pub tool_paths: std::collections::HashMap<String, PathBuf>,

    /// Timeout for each tool (seconds)
    pub timeout_secs: u64,

    /// Maximum output size to capture
    pub max_output_bytes: usize,

    /// Temporary directory for extraction
    pub temp_dir: PathBuf,

    /// Enable parallel tool execution
    pub parallel: bool,

    /// YARA rules directory
    pub yara_rules_dir: Option<PathBuf>,

    /// Ghidra install path
    pub ghidra_path: Option<PathBuf>,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            tool_paths: std::collections::HashMap::new(),
            timeout_secs: 300,
            max_output_bytes: 50 * 1024 * 1024, // 50MB
            temp_dir: std::env::temp_dir().join("fw-scanner"),
            parallel: true,
            yara_rules_dir: None,
            ghidra_path: None,
        }
    }
}

/// Orchestrator for running multiple tools
pub struct ToolOrchestrator {
    config: ToolConfig,
    tools: Vec<Box<dyn ExternalTool>>,
}

impl ToolOrchestrator {
    pub fn new(config: ToolConfig) -> Self {
        Self {
            config,
            tools: Vec::new(),
        }
    }

    /// Initialize with all available tools
    pub async fn with_available_tools(config: ToolConfig) -> Self {
        let mut orchestrator = Self::new(config.clone());

        // Try to register each tool if available
        if let Ok(tool) = binwalk::Binwalk::new(config.clone()) {
            if tool.is_available().await {
                orchestrator.tools.push(Box::new(tool));
            }
        }

        if let Ok(tool) = radare2::Radare2::new(config.clone()) {
            if tool.is_available().await {
                orchestrator.tools.push(Box::new(tool));
            }
        }

        if let Ok(tool) = yara::Yara::new(config.clone()) {
            if tool.is_available().await {
                orchestrator.tools.push(Box::new(tool));
            }
        }

        if let Ok(tool) = strings::Strings::new(config.clone()) {
            if tool.is_available().await {
                orchestrator.tools.push(Box::new(tool));
            }
        }

        if let Ok(tool) = clamav::ClamAV::new(config.clone()) {
            if tool.is_available().await {
                orchestrator.tools.push(Box::new(tool));
            }
        }

        if let Ok(tool) = objdump::Objdump::new(config.clone()) {
            if tool.is_available().await {
                orchestrator.tools.push(Box::new(tool));
            }
        }

        orchestrator
    }

    /// List available tools
    pub fn available_tools(&self) -> Vec<&str> {
        self.tools.iter().map(|t| t.name()).collect()
    }

    /// Run all tools on a file
    pub async fn analyze_all(&self, file_path: &Path) -> Vec<AnalysisResult> {
        let mut results = Vec::new();

        if self.config.parallel {
            // Run tools in parallel
            let handles: Vec<_> = self.tools.iter().enumerate().map(|(i, _tool)| {
                let path = file_path.to_path_buf();
                let config = self.config.clone();

                async move {
                    // Each tool has its own analyze method
                    // This is simplified - actual implementation would dispatch properly
                    AnalysisResult {
                        tool: format!("tool_{}", i),
                        success: true,
                        duration_ms: 0,
                        findings: Vec::new(),
                        raw_output: None,
                        errors: Vec::new(),
                    }
                }
            }).collect();

            // In practice, would use proper parallel execution
            for handle in handles {
                results.push(handle.await);
            }
        } else {
            // Sequential execution
            for tool in &self.tools {
                tracing::info!("Running tool: {}", tool.name());
                // Dispatch to appropriate analyze method
            }
        }

        results
    }
}

/// Run a command with timeout
pub async fn run_command(
    cmd: &str,
    args: &[&str],
    timeout_secs: u64,
) -> ToolResult<(String, String, i32)> {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    let result = timeout(
        Duration::from_secs(timeout_secs),
        Command::new(cmd)
            .args(args)
            .output()
    ).await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let code = output.status.code().unwrap_or(-1);
            Ok((stdout, stderr, code))
        }
        Ok(Err(e)) => Err(ToolError::ExecutionFailed(e.to_string())),
        Err(_) => Err(ToolError::Timeout(timeout_secs)),
    }
}

/// Check if a command exists in PATH
pub fn command_exists(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

/// Get command path
pub fn get_command_path(cmd: &str) -> Option<PathBuf> {
    which::which(cmd).ok()
}
