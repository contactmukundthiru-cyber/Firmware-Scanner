//! Ghidra integration for advanced binary analysis
//!
//! Ghidra is NSA's reverse engineering tool for software analysis.

use crate::{
    ExternalTool, Finding, FindingCategory, FindingSeverity,
    ToolConfig, ToolError, ToolResult, run_command,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Ghidra headless analyzer
pub struct Ghidra {
    config: ToolConfig,
    ghidra_path: Option<PathBuf>,
    headless_script: Option<PathBuf>,
}

impl Ghidra {
    pub fn new(config: ToolConfig) -> ToolResult<Self> {
        // Try to find Ghidra installation
        let ghidra_path = config.ghidra_path.clone()
            .or_else(|| std::env::var("GHIDRA_HOME").ok().map(PathBuf::from))
            .or_else(|| {
                // Common install locations
                let locations = vec![
                    "/opt/ghidra",
                    "/usr/share/ghidra",
                    "C:\\Program Files\\Ghidra",
                    "C:\\ghidra",
                ];
                locations.into_iter()
                    .map(PathBuf::from)
                    .find(|p| p.exists())
            });

        let headless_script = ghidra_path.as_ref().map(|p| {
            #[cfg(windows)]
            { p.join("support").join("analyzeHeadless.bat") }
            #[cfg(not(windows))]
            { p.join("support").join("analyzeHeadless") }
        }).filter(|p| p.exists());

        Ok(Self {
            config,
            ghidra_path,
            headless_script,
        })
    }

    /// Run headless analysis
    pub async fn analyze(&self, file_path: &Path, project_dir: &Path) -> ToolResult<GhidraResult> {
        let script = self.headless_script.as_ref()
            .ok_or_else(|| ToolError::NotFound("ghidra analyzeHeadless".to_string()))?;

        tokio::fs::create_dir_all(project_dir).await?;

        let project_name = "fw_analysis";
        let start = std::time::Instant::now();

        // Run headless analysis with built-in scripts
        let (stdout, stderr, code) = run_command(
            script.to_str().unwrap(),
            &[
                project_dir.to_str().unwrap(),
                project_name,
                "-import", file_path.to_str().unwrap(),
                "-analysisTimeoutPerFile", &self.config.timeout_secs.to_string(),
                "-scriptPath", script.parent().unwrap().to_str().unwrap(),
                "-postScript", "FunctionExporter.java",
                "-deleteProject",  // Clean up after
            ],
            self.config.timeout_secs * 2,
        ).await?;

        // Parse output for functions and analysis results
        let functions = parse_ghidra_functions(&stdout);

        Ok(GhidraResult {
            duration_ms: start.elapsed().as_millis() as u64,
            functions,
            raw_output: stdout,
            errors: if stderr.is_empty() { Vec::new() } else { vec![stderr] },
        })
    }

    /// Export decompiled code
    pub async fn decompile(&self, file_path: &Path, project_dir: &Path) -> ToolResult<String> {
        let script = self.headless_script.as_ref()
            .ok_or_else(|| ToolError::NotFound("ghidra analyzeHeadless".to_string()))?;

        tokio::fs::create_dir_all(project_dir).await?;

        let output_file = project_dir.join("decompiled.c");
        let project_name = "fw_decompile";

        let (stdout, _stderr, _code) = run_command(
            script.to_str().unwrap(),
            &[
                project_dir.to_str().unwrap(),
                project_name,
                "-import", file_path.to_str().unwrap(),
                "-postScript", "DecompileExporter.java", output_file.to_str().unwrap(),
                "-deleteProject",
            ],
            self.config.timeout_secs * 3,
        ).await?;

        // Try to read decompiled output
        let decompiled = tokio::fs::read_to_string(&output_file)
            .await
            .unwrap_or_else(|_| stdout);

        Ok(decompiled)
    }

    /// Find interesting functions
    pub async fn find_functions(&self, file_path: &Path, patterns: &[&str]) -> ToolResult<Vec<GhidraFunction>> {
        let temp_dir = tempfile::tempdir()?;
        let result = self.analyze(file_path, temp_dir.path()).await?;

        let matching: Vec<_> = result.functions.into_iter()
            .filter(|f| {
                patterns.iter().any(|p| {
                    f.name.to_lowercase().contains(&p.to_lowercase())
                })
            })
            .collect();

        Ok(matching)
    }

    /// Convert to generic findings
    pub fn to_findings(&self, result: &GhidraResult) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find dangerous functions
        let dangerous_patterns = vec![
            ("system", FindingSeverity::High, "Shell execution"),
            ("exec", FindingSeverity::High, "Process execution"),
            ("strcpy", FindingSeverity::Medium, "Unsafe string copy"),
            ("sprintf", FindingSeverity::Medium, "Format string vulnerability risk"),
            ("gets", FindingSeverity::Critical, "Buffer overflow vulnerability"),
        ];

        for func in &result.functions {
            for (pattern, severity, desc) in &dangerous_patterns {
                if func.name.to_lowercase().contains(pattern) {
                    findings.push(Finding {
                        category: FindingCategory::Vulnerability,
                        severity: *severity,
                        title: format!("Dangerous function: {}", func.name),
                        description: format!("{} at address 0x{:X}", desc, func.address),
                        file_path: None,
                        offset: Some(func.address),
                        size: Some(func.size),
                        data: Some(serde_json::json!({
                            "function": func.name,
                            "address": format!("0x{:X}", func.address),
                        })),
                    });
                }
            }
        }

        findings
    }
}

#[async_trait]
impl ExternalTool for Ghidra {
    fn name(&self) -> &str {
        "ghidra"
    }

    async fn is_available(&self) -> bool {
        self.headless_script.is_some()
    }

    async fn version(&self) -> ToolResult<String> {
        if let Some(ref path) = self.ghidra_path {
            // Try to read version from Ghidra installation
            let version_file = path.join("Ghidra").join("application.properties");
            if let Ok(content) = tokio::fs::read_to_string(&version_file).await {
                for line in content.lines() {
                    if line.starts_with("application.version=") {
                        return Ok(line.split('=').nth(1).unwrap_or("unknown").to_string());
                    }
                }
            }
        }
        Ok("unknown".to_string())
    }

    fn executable_path(&self) -> Option<&Path> {
        self.headless_script.as_deref()
    }
}

/// Ghidra analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraResult {
    pub duration_ms: u64,
    pub functions: Vec<GhidraFunction>,
    pub raw_output: String,
    pub errors: Vec<String>,
}

/// Function information from Ghidra
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraFunction {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub calling_convention: Option<String>,
    pub parameters: Vec<String>,
    pub return_type: Option<String>,
}

/// Parse Ghidra output for functions
fn parse_ghidra_functions(output: &str) -> Vec<GhidraFunction> {
    let mut functions = Vec::new();

    // Simple parsing - actual format depends on the Ghidra script used
    for line in output.lines() {
        if line.starts_with("FUNC:") || line.contains("Function:") {
            // Parse function definition
            // Format varies by script, this is simplified
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
                let address = parts.get(2)
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);

                functions.push(GhidraFunction {
                    name,
                    address,
                    size: 0,
                    calling_convention: None,
                    parameters: Vec::new(),
                    return_type: None,
                });
            }
        }
    }

    functions
}
