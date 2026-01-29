//! YARA integration for pattern matching and malware detection
//!
//! YARA is a tool for identifying and classifying malware samples.

use crate::{
    ExternalTool, Finding, FindingCategory, FindingSeverity,
    ToolConfig, ToolError, ToolResult, run_command,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// YARA tool wrapper
pub struct Yara {
    config: ToolConfig,
    executable: Option<PathBuf>,
    rules_dir: Option<PathBuf>,
}

impl Yara {
    pub fn new(config: ToolConfig) -> ToolResult<Self> {
        let executable = config.tool_paths.get("yara")
            .cloned()
            .or_else(|| crate::get_command_path("yara"))
            .or_else(|| crate::get_command_path("yara64"));

        let rules_dir = config.yara_rules_dir.clone();

        Ok(Self { config, executable, rules_dir })
    }

    /// Set rules directory
    pub fn with_rules_dir(mut self, dir: PathBuf) -> Self {
        self.rules_dir = Some(dir);
        self
    }

    /// Scan a file with a specific rule
    pub async fn scan_with_rule(&self, file_path: &Path, rule_path: &Path) -> ToolResult<YaraResult> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("yara".to_string()))?;

        let start = std::time::Instant::now();

        let (stdout, stderr, code) = run_command(
            exe.to_str().unwrap(),
            &["-s", rule_path.to_str().unwrap(), file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let matches = parse_yara_output(&stdout);

        Ok(YaraResult {
            duration_ms: start.elapsed().as_millis() as u64,
            matches,
            rule_file: rule_path.to_path_buf(),
            raw_output: stdout,
            errors: if stderr.is_empty() { Vec::new() } else { vec![stderr] },
        })
    }

    /// Scan a file with all rules in a directory
    pub async fn scan_with_rules_dir(&self, file_path: &Path, rules_dir: &Path) -> ToolResult<Vec<YaraResult>> {
        let mut results = Vec::new();

        let entries = std::fs::read_dir(rules_dir)
            .map_err(|e| ToolError::Io(e))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "yar" || e == "yara").unwrap_or(false) {
                match self.scan_with_rule(file_path, &path).await {
                    Ok(result) => results.push(result),
                    Err(e) => tracing::warn!("YARA rule {} failed: {}", path.display(), e),
                }
            }
        }

        Ok(results)
    }

    /// Scan with embedded rules
    pub async fn scan_with_embedded_rules(&self, file_path: &Path) -> ToolResult<YaraResult> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("yara".to_string()))?;

        // Write embedded rules to temp file
        let temp_rules = tempfile::NamedTempFile::new()?;
        std::fs::write(temp_rules.path(), EMBEDDED_RULES)?;

        let start = std::time::Instant::now();

        let (stdout, stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-s", temp_rules.path().to_str().unwrap(), file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let matches = parse_yara_output(&stdout);

        Ok(YaraResult {
            duration_ms: start.elapsed().as_millis() as u64,
            matches,
            rule_file: temp_rules.path().to_path_buf(),
            raw_output: stdout,
            errors: if stderr.is_empty() { Vec::new() } else { vec![stderr] },
        })
    }

    /// Compile YARA rules
    pub async fn compile_rules(&self, source_path: &Path, output_path: &Path) -> ToolResult<()> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("yara".to_string()))?;

        let yarac = exe.parent()
            .map(|p| p.join("yarac"))
            .filter(|p| p.exists())
            .or_else(|| crate::get_command_path("yarac"))
            .ok_or_else(|| ToolError::NotFound("yarac".to_string()))?;

        let (_stdout, stderr, code) = run_command(
            yarac.to_str().unwrap(),
            &[source_path.to_str().unwrap(), output_path.to_str().unwrap()],
            60,
        ).await?;

        if code != 0 {
            return Err(ToolError::ExecutionFailed(stderr));
        }

        Ok(())
    }

    /// Convert to generic findings
    pub fn to_findings(&self, result: &YaraResult) -> Vec<Finding> {
        result.matches.iter().map(|m| {
            let severity = match m.rule_name.to_lowercase().as_str() {
                s if s.contains("malware") => FindingSeverity::Critical,
                s if s.contains("suspicious") => FindingSeverity::High,
                s if s.contains("backdoor") => FindingSeverity::Critical,
                s if s.contains("exploit") => FindingSeverity::Critical,
                s if s.contains("credential") => FindingSeverity::High,
                s if s.contains("password") => FindingSeverity::Medium,
                s if s.contains("key") => FindingSeverity::Medium,
                s if s.contains("network") => FindingSeverity::Low,
                _ => FindingSeverity::Info,
            };

            let category = match m.rule_name.to_lowercase().as_str() {
                s if s.contains("malware") => FindingCategory::Malware,
                s if s.contains("backdoor") => FindingCategory::Malware,
                s if s.contains("credential") => FindingCategory::Credentials,
                s if s.contains("crypto") => FindingCategory::Encryption,
                s if s.contains("network") => FindingCategory::Networking,
                s if s.contains("telemetry") => FindingCategory::Telemetry,
                _ => FindingCategory::Unknown,
            };

            Finding {
                category,
                severity,
                title: format!("YARA: {}", m.rule_name),
                description: format!("YARA rule '{}' matched {} times", m.rule_name, m.strings.len()),
                file_path: None,
                offset: m.strings.first().map(|s| s.offset),
                size: None,
                data: Some(serde_json::json!({
                    "rule": m.rule_name,
                    "tags": m.tags,
                    "strings": m.strings,
                })),
            }
        }).collect()
    }
}

#[async_trait]
impl ExternalTool for Yara {
    fn name(&self) -> &str {
        "yara"
    }

    async fn is_available(&self) -> bool {
        self.executable.is_some()
    }

    async fn version(&self) -> ToolResult<String> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("yara".to_string()))?;

        let (stdout, _, _) = run_command(
            exe.to_str().unwrap(),
            &["--version"],
            10,
        ).await?;

        Ok(stdout.trim().to_string())
    }

    fn executable_path(&self) -> Option<&Path> {
        self.executable.as_deref()
    }
}

/// YARA scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraResult {
    pub duration_ms: u64,
    pub matches: Vec<YaraMatch>,
    pub rule_file: PathBuf,
    pub raw_output: String,
    pub errors: Vec<String>,
}

/// Individual YARA match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub strings: Vec<YaraString>,
}

/// YARA string match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub identifier: String,
    pub offset: u64,
    pub data: String,
}

/// Parse YARA output
fn parse_yara_output(output: &str) -> Vec<YaraMatch> {
    let mut matches = Vec::new();
    let mut current_match: Option<YaraMatch> = None;

    for line in output.lines() {
        // Rule match line: rule_name [tags] file_path
        if !line.starts_with("0x") && !line.is_empty() {
            if let Some(m) = current_match.take() {
                matches.push(m);
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let rule_name = parts[0].to_string();
                let tags = if parts.len() > 1 && parts[1].starts_with('[') {
                    parts[1].trim_matches(|c| c == '[' || c == ']')
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect()
                } else {
                    Vec::new()
                };

                current_match = Some(YaraMatch {
                    rule_name,
                    tags,
                    strings: Vec::new(),
                });
            }
        }
        // String match line: 0x123:$identifier: data
        else if line.starts_with("0x") {
            if let Some(ref mut m) = current_match {
                let re = regex::Regex::new(r"0x([0-9a-fA-F]+):(\$\w+):\s*(.*)").unwrap();
                if let Some(caps) = re.captures(line) {
                    let offset = u64::from_str_radix(&caps[1], 16).unwrap_or(0);
                    let identifier = caps[2].to_string();
                    let data = caps[3].to_string();

                    m.strings.push(YaraString {
                        identifier,
                        offset,
                        data,
                    });
                }
            }
        }
    }

    if let Some(m) = current_match {
        matches.push(m);
    }

    matches
}

/// Embedded YARA rules for firmware analysis
const EMBEDDED_RULES: &str = r#"
rule suspicious_hardcoded_ip {
    meta:
        description = "Detects hardcoded IP addresses"
        severity = "medium"
    strings:
        $ip1 = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/
    condition:
        $ip1
}

rule potential_backdoor {
    meta:
        description = "Potential backdoor indicators"
        severity = "high"
    strings:
        $s1 = "backdoor" nocase
        $s2 = "rootkit" nocase
        $s3 = "/bin/sh -i" nocase
        $s4 = "reverse shell" nocase
        $s5 = "bind shell" nocase
        $s6 = "nc -e" nocase
        $s7 = "netcat" nocase
    condition:
        any of them
}

rule hardcoded_credentials {
    meta:
        description = "Hardcoded credentials"
        severity = "critical"
    strings:
        $s1 = "password=" nocase
        $s2 = "passwd=" nocase
        $s3 = "api_key=" nocase
        $s4 = "apikey=" nocase
        $s5 = "secret=" nocase
        $s6 = "token=" nocase
        $s7 = "-----BEGIN RSA PRIVATE KEY-----"
        $s8 = "-----BEGIN PRIVATE KEY-----"
        $s9 = "-----BEGIN EC PRIVATE KEY-----"
        $s10 = "-----BEGIN OPENSSH PRIVATE KEY-----"
    condition:
        any of them
}

rule telemetry_indicators {
    meta:
        description = "Telemetry and tracking indicators"
        severity = "medium"
    strings:
        $s1 = "analytics" nocase
        $s2 = "telemetry" nocase
        $s3 = "tracking" nocase
        $s4 = "google-analytics" nocase
        $s5 = "crashlytics" nocase
        $s6 = "mixpanel" nocase
        $s7 = "amplitude" nocase
        $s8 = "segment.io" nocase
        $s9 = "user_agent" nocase
        $s10 = "device_id" nocase
    condition:
        2 of them
}

rule network_capabilities {
    meta:
        description = "Network communication capabilities"
        severity = "info"
    strings:
        $http = "http://" nocase
        $https = "https://" nocase
        $ftp = "ftp://" nocase
        $socket = "socket" nocase
        $connect = "connect" nocase
        $curl = "curl" nocase
        $wget = "wget" nocase
    condition:
        3 of them
}

rule crypto_usage {
    meta:
        description = "Cryptographic function usage"
        severity = "info"
    strings:
        $aes = "AES" nocase
        $des = "DES" nocase
        $rsa = "RSA" nocase
        $sha = "SHA" nocase
        $md5 = "MD5" nocase
        $ssl = "SSL" nocase
        $tls = "TLS" nocase
        $openssl = "openssl" nocase
    condition:
        any of them
}

rule update_mechanism {
    meta:
        description = "Remote update mechanism"
        severity = "medium"
    strings:
        $s1 = "update" nocase
        $s2 = "upgrade" nocase
        $s3 = "firmware" nocase
        $s4 = "download" nocase
        $s5 = "ota" nocase
        $s6 = "over-the-air" nocase
    condition:
        3 of them
}

rule debug_information {
    meta:
        description = "Debug information left in binary"
        severity = "low"
    strings:
        $s1 = "DEBUG" nocase
        $s2 = "TODO" nocase
        $s3 = "FIXME" nocase
        $s4 = "assert" nocase
        $s5 = "printf" nocase
        $s6 = "__FILE__"
        $s7 = "__LINE__"
    condition:
        3 of them
}

rule shell_commands {
    meta:
        description = "Shell command execution"
        severity = "medium"
    strings:
        $s1 = "system(" nocase
        $s2 = "popen(" nocase
        $s3 = "exec(" nocase
        $s4 = "/bin/sh" nocase
        $s5 = "/bin/bash" nocase
        $s6 = "cmd.exe" nocase
        $s7 = "powershell" nocase
    condition:
        any of them
}

rule known_vulnerable_libs {
    meta:
        description = "Known vulnerable library versions"
        severity = "high"
    strings:
        $openssl_old = "OpenSSL 0." nocase
        $openssl_1_0 = "OpenSSL 1.0" nocase
        $busybox_old = "BusyBox v1.1" nocase
        $dropbear_old = "dropbear_201" nocase
        $uclibc_old = "uClibc 0." nocase
    condition:
        any of them
}
"#;
