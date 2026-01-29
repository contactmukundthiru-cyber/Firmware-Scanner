//! objdump/readelf integration for ELF binary analysis
//!
//! GNU binutils tools for binary inspection.

use crate::{
    ExternalTool, Finding, FindingCategory, FindingSeverity,
    ToolConfig, ToolError, ToolResult, run_command,
};
use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// objdump/readelf wrapper
pub struct Objdump {
    config: ToolConfig,
    objdump_executable: Option<PathBuf>,
    readelf_executable: Option<PathBuf>,
}

impl Objdump {
    pub fn new(config: ToolConfig) -> ToolResult<Self> {
        // Try various objdump names (cross-compile variants)
        let objdump_executable = config.tool_paths.get("objdump")
            .cloned()
            .or_else(|| crate::get_command_path("objdump"))
            .or_else(|| crate::get_command_path("llvm-objdump"))
            .or_else(|| crate::get_command_path("arm-linux-gnueabi-objdump"))
            .or_else(|| crate::get_command_path("mips-linux-gnu-objdump"));

        let readelf_executable = config.tool_paths.get("readelf")
            .cloned()
            .or_else(|| crate::get_command_path("readelf"))
            .or_else(|| crate::get_command_path("llvm-readelf"));

        Ok(Self {
            config,
            objdump_executable,
            readelf_executable,
        })
    }

    /// Get file headers
    pub async fn headers(&self, file_path: &Path) -> ToolResult<ElfHeaders> {
        let exe = self.readelf_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("readelf".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-h", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        parse_elf_headers(&stdout)
    }

    /// Get sections
    pub async fn sections(&self, file_path: &Path) -> ToolResult<Vec<ElfSection>> {
        let exe = self.readelf_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("readelf".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-S", "-W", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        Ok(parse_sections(&stdout))
    }

    /// Get symbols
    pub async fn symbols(&self, file_path: &Path) -> ToolResult<Vec<ElfSymbol>> {
        let exe = self.readelf_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("readelf".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-s", "-W", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        Ok(parse_symbols(&stdout))
    }

    /// Get dynamic symbols (imports/exports)
    pub async fn dynamic_symbols(&self, file_path: &Path) -> ToolResult<Vec<ElfSymbol>> {
        let exe = self.readelf_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("readelf".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["--dyn-syms", "-W", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        Ok(parse_symbols(&stdout))
    }

    /// Get needed libraries
    pub async fn needed_libraries(&self, file_path: &Path) -> ToolResult<Vec<String>> {
        let exe = self.readelf_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("readelf".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-d", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let re = Regex::new(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]").unwrap();
        let libraries: Vec<String> = re.captures_iter(&stdout)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();

        Ok(libraries)
    }

    /// Disassemble a section
    pub async fn disassemble(&self, file_path: &Path, section: Option<&str>) -> ToolResult<String> {
        let exe = self.objdump_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("objdump".to_string()))?;

        let mut args = vec!["-d"];
        if let Some(sec) = section {
            args.push("-j");
            args.push(sec);
        }
        args.push(file_path.to_str().unwrap());

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &args,
            self.config.timeout_secs,
        ).await?;

        Ok(stdout)
    }

    /// Get relocations
    pub async fn relocations(&self, file_path: &Path) -> ToolResult<Vec<ElfRelocation>> {
        let exe = self.readelf_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("readelf".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-r", "-W", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        Ok(parse_relocations(&stdout))
    }

    /// Full analysis
    pub async fn analyze(&self, file_path: &Path) -> ToolResult<ObjdumpAnalysis> {
        let start = std::time::Instant::now();

        let headers = self.headers(file_path).await.ok();
        let sections = self.sections(file_path).await.unwrap_or_default();
        let symbols = self.symbols(file_path).await.unwrap_or_default();
        let dynamic_symbols = self.dynamic_symbols(file_path).await.unwrap_or_default();
        let libraries = self.needed_libraries(file_path).await.unwrap_or_default();

        Ok(ObjdumpAnalysis {
            duration_ms: start.elapsed().as_millis() as u64,
            headers,
            sections,
            symbols,
            dynamic_symbols,
            libraries,
        })
    }

    /// Convert to generic findings
    pub fn to_findings(&self, analysis: &ObjdumpAnalysis) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for dangerous functions
        let dangerous = vec!["gets", "strcpy", "strcat", "sprintf", "scanf", "system", "popen"];

        for sym in &analysis.dynamic_symbols {
            if dangerous.iter().any(|&d| sym.name.contains(d)) {
                findings.push(Finding {
                    category: FindingCategory::Vulnerability,
                    severity: if sym.name.contains("gets") {
                        FindingSeverity::Critical
                    } else {
                        FindingSeverity::Medium
                    },
                    title: format!("Dangerous function import: {}", sym.name),
                    description: format!("Binary imports potentially dangerous function '{}'", sym.name),
                    file_path: None,
                    offset: Some(sym.address),
                    size: None,
                    data: Some(serde_json::json!({
                        "function": sym.name,
                        "symbol_type": sym.symbol_type,
                    })),
                });
            }
        }

        // Check for suspicious sections
        for section in &analysis.sections {
            if section.flags.contains('X') && section.flags.contains('W') {
                findings.push(Finding {
                    category: FindingCategory::Vulnerability,
                    severity: FindingSeverity::Medium,
                    title: format!("Writable and executable section: {}", section.name),
                    description: "Section has both write and execute permissions, potential security risk".to_string(),
                    file_path: None,
                    offset: Some(section.address),
                    size: Some(section.size),
                    data: Some(serde_json::json!({
                        "section": section.name,
                        "flags": section.flags,
                    })),
                });
            }
        }

        findings
    }
}

#[async_trait]
impl ExternalTool for Objdump {
    fn name(&self) -> &str {
        "objdump/readelf"
    }

    async fn is_available(&self) -> bool {
        self.objdump_executable.is_some() || self.readelf_executable.is_some()
    }

    async fn version(&self) -> ToolResult<String> {
        let exe = self.objdump_executable.as_ref()
            .or(self.readelf_executable.as_ref())
            .ok_or_else(|| ToolError::NotFound("objdump/readelf".to_string()))?;

        let (stdout, _, _) = run_command(
            exe.to_str().unwrap(),
            &["--version"],
            10,
        ).await?;

        Ok(stdout.lines().next().unwrap_or("unknown").to_string())
    }

    fn executable_path(&self) -> Option<&Path> {
        self.objdump_executable.as_deref()
            .or(self.readelf_executable.as_deref())
    }
}

/// ELF file headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfHeaders {
    pub class: String,
    pub data: String,
    pub os_abi: String,
    pub file_type: String,
    pub machine: String,
    pub entry_point: u64,
}

/// ELF section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSection {
    pub name: String,
    pub section_type: String,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: String,
}

/// ELF symbol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub symbol_type: String,
    pub bind: String,
    pub visibility: String,
}

/// ELF relocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfRelocation {
    pub offset: u64,
    pub relocation_type: String,
    pub symbol_name: String,
}

/// Full objdump analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjdumpAnalysis {
    pub duration_ms: u64,
    pub headers: Option<ElfHeaders>,
    pub sections: Vec<ElfSection>,
    pub symbols: Vec<ElfSymbol>,
    pub dynamic_symbols: Vec<ElfSymbol>,
    pub libraries: Vec<String>,
}

/// Parse ELF headers from readelf output
fn parse_elf_headers(output: &str) -> ToolResult<ElfHeaders> {
    let mut headers = ElfHeaders {
        class: String::new(),
        data: String::new(),
        os_abi: String::new(),
        file_type: String::new(),
        machine: String::new(),
        entry_point: 0,
    };

    for line in output.lines() {
        if line.contains("Class:") {
            headers.class = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.contains("Data:") {
            headers.data = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.contains("OS/ABI:") {
            headers.os_abi = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.contains("Type:") {
            headers.file_type = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.contains("Machine:") {
            headers.machine = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.contains("Entry point") {
            let addr = line.split(':').nth(1).unwrap_or("0").trim();
            headers.entry_point = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap_or(0);
        }
    }

    Ok(headers)
}

/// Parse sections from readelf output
fn parse_sections(output: &str) -> Vec<ElfSection> {
    let mut sections = Vec::new();
    let re = Regex::new(r"\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+).*\s+([WAXMSI]+)?").unwrap();

    for line in output.lines() {
        if let Some(caps) = re.captures(line) {
            sections.push(ElfSection {
                name: caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string(),
                section_type: caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string(),
                address: caps.get(3).and_then(|m| u64::from_str_radix(m.as_str(), 16).ok()).unwrap_or(0),
                offset: caps.get(4).and_then(|m| u64::from_str_radix(m.as_str(), 16).ok()).unwrap_or(0),
                size: caps.get(5).and_then(|m| u64::from_str_radix(m.as_str(), 16).ok()).unwrap_or(0),
                flags: caps.get(6).map(|m| m.as_str()).unwrap_or("").to_string(),
            });
        }
    }

    sections
}

/// Parse symbols from readelf output
fn parse_symbols(output: &str) -> Vec<ElfSymbol> {
    let mut symbols = Vec::new();
    let re = Regex::new(r"\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)").unwrap();

    for line in output.lines() {
        if let Some(caps) = re.captures(line) {
            let name = caps.get(6).map(|m| m.as_str()).unwrap_or("");
            if !name.is_empty() && name != "Name" {
                symbols.push(ElfSymbol {
                    name: name.to_string(),
                    address: caps.get(1).and_then(|m| u64::from_str_radix(m.as_str(), 16).ok()).unwrap_or(0),
                    size: caps.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                    symbol_type: caps.get(3).map(|m| m.as_str()).unwrap_or("").to_string(),
                    bind: caps.get(4).map(|m| m.as_str()).unwrap_or("").to_string(),
                    visibility: caps.get(5).map(|m| m.as_str()).unwrap_or("").to_string(),
                });
            }
        }
    }

    symbols
}

/// Parse relocations from readelf output
fn parse_relocations(output: &str) -> Vec<ElfRelocation> {
    let mut relocations = Vec::new();
    let re = Regex::new(r"([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(\S+)\s+[0-9a-fA-F]*\s*(\S*)").unwrap();

    for line in output.lines() {
        if let Some(caps) = re.captures(line) {
            relocations.push(ElfRelocation {
                offset: caps.get(1).and_then(|m| u64::from_str_radix(m.as_str(), 16).ok()).unwrap_or(0),
                relocation_type: caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string(),
                symbol_name: caps.get(3).map(|m| m.as_str()).unwrap_or("").to_string(),
            });
        }
    }

    relocations
}
