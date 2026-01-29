//! Radare2/Rizin integration for binary analysis and disassembly
//!
//! Radare2 is a complete framework for reverse-engineering and analyzing binaries.

use crate::{
    AnalysisResult, ExternalTool, Finding, FindingCategory, FindingSeverity,
    ToolConfig, ToolError, ToolResult, command_exists, run_command,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Radare2 tool wrapper
pub struct Radare2 {
    config: ToolConfig,
    executable: Option<PathBuf>,
    use_rizin: bool,
}

impl Radare2 {
    pub fn new(config: ToolConfig) -> ToolResult<Self> {
        // Try radare2 first, then rizin
        let (executable, use_rizin) = if let Some(path) = config.tool_paths.get("radare2") {
            (Some(path.clone()), false)
        } else if let Some(path) = config.tool_paths.get("rizin") {
            (Some(path.clone()), true)
        } else if let Some(path) = crate::get_command_path("r2") {
            (Some(path), false)
        } else if let Some(path) = crate::get_command_path("radare2") {
            (Some(path), false)
        } else if let Some(path) = crate::get_command_path("rizin") {
            (Some(path), true)
        } else {
            (None, false)
        };

        Ok(Self { config, executable, use_rizin })
    }

    /// Get binary information
    pub async fn info(&self, file_path: &Path) -> ToolResult<BinaryInfo> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let start = std::time::Instant::now();

        // r2 -q -c 'iI' binary - get info
        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-q", "-c", "iIj", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let info: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_default();

        Ok(BinaryInfo {
            duration_ms: start.elapsed().as_millis() as u64,
            arch: info["bin"]["arch"].as_str().unwrap_or("unknown").to_string(),
            bits: info["bin"]["bits"].as_u64().unwrap_or(0) as u32,
            os: info["bin"]["os"].as_str().unwrap_or("unknown").to_string(),
            machine: info["bin"]["machine"].as_str().unwrap_or("unknown").to_string(),
            endian: info["bin"]["endian"].as_str().unwrap_or("unknown").to_string(),
            is_stripped: info["bin"]["stripped"].as_bool().unwrap_or(false),
            has_nx: info["bin"]["nx"].as_bool().unwrap_or(false),
            has_pic: info["bin"]["pic"].as_bool().unwrap_or(false),
            has_canary: info["bin"]["canary"].as_bool().unwrap_or(false),
            compiler: info["bin"]["compiler"].as_str().map(|s| s.to_string()),
            raw_info: info,
        })
    }

    /// List all strings
    pub async fn strings(&self, file_path: &Path) -> ToolResult<Vec<R2String>> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-q", "-c", "izj", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let strings: Vec<R2String> = serde_json::from_str(&stdout)
            .unwrap_or_default();

        Ok(strings)
    }

    /// List all functions
    pub async fn functions(&self, file_path: &Path) -> ToolResult<Vec<R2Function>> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-q", "-c", "aaa; aflj", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let functions: Vec<R2Function> = serde_json::from_str(&stdout)
            .unwrap_or_default();

        Ok(functions)
    }

    /// List imports
    pub async fn imports(&self, file_path: &Path) -> ToolResult<Vec<R2Import>> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-q", "-c", "iij", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let imports: Vec<R2Import> = serde_json::from_str(&stdout)
            .unwrap_or_default();

        Ok(imports)
    }

    /// List exports
    pub async fn exports(&self, file_path: &Path) -> ToolResult<Vec<R2Export>> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-q", "-c", "iEj", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let exports: Vec<R2Export> = serde_json::from_str(&stdout)
            .unwrap_or_default();

        Ok(exports)
    }

    /// List sections
    pub async fn sections(&self, file_path: &Path) -> ToolResult<Vec<R2Section>> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-q", "-c", "iSj", file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let sections: Vec<R2Section> = serde_json::from_str(&stdout)
            .unwrap_or_default();

        Ok(sections)
    }

    /// Search for cross-references
    pub async fn xrefs(&self, file_path: &Path, address: u64) -> ToolResult<Vec<R2Xref>> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let cmd = format!("aaa; axtj @ {}", address);
        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-q", "-c", &cmd, file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let xrefs: Vec<R2Xref> = serde_json::from_str(&stdout)
            .unwrap_or_default();

        Ok(xrefs)
    }

    /// Disassemble at address
    pub async fn disassemble(&self, file_path: &Path, address: u64, count: usize) -> ToolResult<String> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let cmd = format!("pd {} @ {}", count, address);
        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-q", "-c", &cmd, file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        Ok(stdout)
    }

    /// Run custom r2 command
    pub async fn command(&self, file_path: &Path, cmd: &str) -> ToolResult<String> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-q", "-c", cmd, file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        Ok(stdout)
    }

    /// Analyze security features
    pub async fn security_check(&self, file_path: &Path) -> ToolResult<SecurityAnalysis> {
        let info = self.info(file_path).await?;
        let imports = self.imports(file_path).await.unwrap_or_default();

        let dangerous_functions: Vec<String> = imports.iter()
            .filter(|i| is_dangerous_function(&i.name))
            .map(|i| i.name.clone())
            .collect();

        let crypto_functions: Vec<String> = imports.iter()
            .filter(|i| is_crypto_function(&i.name))
            .map(|i| i.name.clone())
            .collect();

        let network_functions: Vec<String> = imports.iter()
            .filter(|i| is_network_function(&i.name))
            .map(|i| i.name.clone())
            .collect();

        Ok(SecurityAnalysis {
            has_nx: info.has_nx,
            has_pic: info.has_pic,
            has_canary: info.has_canary,
            is_stripped: info.is_stripped,
            dangerous_functions,
            crypto_functions,
            network_functions,
        })
    }

    /// Convert to generic findings
    pub fn to_findings(&self, security: &SecurityAnalysis) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !security.has_nx {
            findings.push(Finding {
                category: FindingCategory::Vulnerability,
                severity: FindingSeverity::Medium,
                title: "NX (No-Execute) disabled".to_string(),
                description: "Binary does not have NX protection, allowing code execution in data sections".to_string(),
                file_path: None,
                offset: None,
                size: None,
                data: None,
            });
        }

        if !security.has_canary {
            findings.push(Finding {
                category: FindingCategory::Vulnerability,
                severity: FindingSeverity::Low,
                title: "Stack canary disabled".to_string(),
                description: "Binary does not use stack canaries for buffer overflow protection".to_string(),
                file_path: None,
                offset: None,
                size: None,
                data: None,
            });
        }

        for func in &security.dangerous_functions {
            findings.push(Finding {
                category: FindingCategory::Vulnerability,
                severity: FindingSeverity::Medium,
                title: format!("Dangerous function: {}", func),
                description: format!("Binary uses potentially dangerous function '{}' which may lead to vulnerabilities", func),
                file_path: None,
                offset: None,
                size: None,
                data: Some(serde_json::json!({"function": func})),
            });
        }

        for func in &security.crypto_functions {
            findings.push(Finding {
                category: FindingCategory::Encryption,
                severity: FindingSeverity::Info,
                title: format!("Crypto function: {}", func),
                description: format!("Binary uses cryptographic function '{}'", func),
                file_path: None,
                offset: None,
                size: None,
                data: Some(serde_json::json!({"function": func})),
            });
        }

        for func in &security.network_functions {
            findings.push(Finding {
                category: FindingCategory::Networking,
                severity: FindingSeverity::Info,
                title: format!("Network function: {}", func),
                description: format!("Binary uses networking function '{}'", func),
                file_path: None,
                offset: None,
                size: None,
                data: Some(serde_json::json!({"function": func})),
            });
        }

        findings
    }
}

#[async_trait]
impl ExternalTool for Radare2 {
    fn name(&self) -> &str {
        if self.use_rizin { "rizin" } else { "radare2" }
    }

    async fn is_available(&self) -> bool {
        self.executable.is_some()
    }

    async fn version(&self) -> ToolResult<String> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("radare2/rizin".to_string()))?;

        let (stdout, _, _) = run_command(
            exe.to_str().unwrap(),
            &["-v"],
            10,
        ).await?;

        Ok(stdout.lines().next().unwrap_or("unknown").to_string())
    }

    fn executable_path(&self) -> Option<&Path> {
        self.executable.as_deref()
    }
}

/// Binary information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub duration_ms: u64,
    pub arch: String,
    pub bits: u32,
    pub os: String,
    pub machine: String,
    pub endian: String,
    pub is_stripped: bool,
    pub has_nx: bool,
    pub has_pic: bool,
    pub has_canary: bool,
    pub compiler: Option<String>,
    pub raw_info: serde_json::Value,
}

/// String from binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2String {
    pub vaddr: u64,
    pub paddr: u64,
    pub ordinal: u32,
    pub size: u32,
    #[serde(rename = "type")]
    pub string_type: String,
    pub string: String,
}

/// Function from binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2Function {
    pub offset: u64,
    pub name: String,
    pub size: u64,
    #[serde(default)]
    pub cc: Option<String>,
    #[serde(default)]
    pub nargs: u32,
    #[serde(default)]
    pub nbbs: u32,
}

/// Import entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2Import {
    pub ordinal: u32,
    pub plt: u64,
    pub bind: String,
    #[serde(rename = "type")]
    pub import_type: String,
    pub name: String,
}

/// Export entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2Export {
    pub name: String,
    pub demname: Option<String>,
    pub flagname: String,
    pub realname: String,
    pub ordinal: u32,
    pub bind: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub export_type: String,
    pub vaddr: u64,
    pub paddr: u64,
}

/// Section entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2Section {
    pub name: String,
    pub size: u64,
    pub vsize: u64,
    pub paddr: u64,
    pub vaddr: u64,
    pub perm: String,
}

/// Cross-reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2Xref {
    pub from: u64,
    pub to: u64,
    #[serde(rename = "type")]
    pub xref_type: String,
}

/// Security analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysis {
    pub has_nx: bool,
    pub has_pic: bool,
    pub has_canary: bool,
    pub is_stripped: bool,
    pub dangerous_functions: Vec<String>,
    pub crypto_functions: Vec<String>,
    pub network_functions: Vec<String>,
}

/// Check if function is dangerous
fn is_dangerous_function(name: &str) -> bool {
    const DANGEROUS: &[&str] = &[
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
        "scanf", "sscanf", "fscanf", "vscanf", "vsscanf", "vfscanf",
        "system", "popen", "exec", "execl", "execle", "execlp", "execv", "execvp", "execvpe",
        "realpath", "getwd", "tmpnam", "tempnam", "mktemp",
    ];

    let lower = name.to_lowercase();
    DANGEROUS.iter().any(|&d| lower.contains(d))
}

/// Check if function is crypto-related
fn is_crypto_function(name: &str) -> bool {
    const CRYPTO: &[&str] = &[
        "aes", "des", "rsa", "sha", "md5", "md4",
        "encrypt", "decrypt", "cipher", "hash",
        "ssl", "tls", "openssl", "mbedtls", "wolfssl",
        "hmac", "pbkdf", "ecdsa", "ecdh", "curve25519",
    ];

    let lower = name.to_lowercase();
    CRYPTO.iter().any(|&c| lower.contains(c))
}

/// Check if function is network-related
fn is_network_function(name: &str) -> bool {
    const NETWORK: &[&str] = &[
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
        "gethostbyname", "getaddrinfo",
        "http", "https", "ftp", "ssh", "telnet",
        "curl", "wget", "fetch",
    ];

    let lower = name.to_lowercase();
    NETWORK.iter().any(|&n| lower.contains(n))
}
