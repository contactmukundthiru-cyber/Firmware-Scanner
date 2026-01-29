//! Enhanced string extraction and analysis
//!
//! Provides intelligent string extraction with categorization.

use crate::{
    ExternalTool, Finding, FindingCategory, FindingSeverity,
    ToolConfig, ToolError, ToolResult, run_command,
};
use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Strings extraction tool
pub struct Strings {
    config: ToolConfig,
    executable: Option<PathBuf>,
}

impl Strings {
    pub fn new(config: ToolConfig) -> ToolResult<Self> {
        let executable = config.tool_paths.get("strings")
            .cloned()
            .or_else(|| crate::get_command_path("strings"));

        Ok(Self { config, executable })
    }

    /// Extract all strings from a file
    pub async fn extract(&self, file_path: &Path, min_length: usize) -> ToolResult<StringsResult> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("strings".to_string()))?;

        let start = std::time::Instant::now();

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-n", &min_length.to_string(), file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let strings: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();
        let categorized = categorize_strings(&strings);

        Ok(StringsResult {
            duration_ms: start.elapsed().as_millis() as u64,
            total_count: strings.len(),
            strings,
            categorized,
        })
    }

    /// Extract strings with offset information
    pub async fn extract_with_offsets(&self, file_path: &Path, min_length: usize) -> ToolResult<Vec<StringWithOffset>> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("strings".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-t", "x", "-n", &min_length.to_string(), file_path.to_str().unwrap()],
            self.config.timeout_secs,
        ).await?;

        let mut results = Vec::new();
        let re = Regex::new(r"^\s*([0-9a-fA-F]+)\s+(.+)$").unwrap();

        for line in stdout.lines() {
            if let Some(caps) = re.captures(line) {
                let offset = u64::from_str_radix(&caps[1], 16).unwrap_or(0);
                let string = caps[2].to_string();
                let category = categorize_string(&string);

                results.push(StringWithOffset {
                    offset,
                    string,
                    category,
                });
            }
        }

        Ok(results)
    }

    /// Search for specific patterns
    pub async fn search_patterns(&self, file_path: &Path, patterns: &[&str]) -> ToolResult<PatternSearchResult> {
        let all_strings = self.extract_with_offsets(file_path, 4).await?;

        let mut matches: HashMap<String, Vec<StringWithOffset>> = HashMap::new();

        for pattern in patterns {
            let re = Regex::new(pattern).ok();
            let matching: Vec<_> = all_strings.iter()
                .filter(|s| {
                    if let Some(ref re) = re {
                        re.is_match(&s.string)
                    } else {
                        s.string.contains(pattern)
                    }
                })
                .cloned()
                .collect();

            if !matching.is_empty() {
                matches.insert(pattern.to_string(), matching);
            }
        }

        Ok(PatternSearchResult { matches })
    }

    /// Find URLs in binary
    pub async fn find_urls(&self, file_path: &Path) -> ToolResult<Vec<UrlMatch>> {
        let strings = self.extract_with_offsets(file_path, 8).await?;

        let url_patterns = vec![
            (Regex::new(r#"https?://[^\s"'<>]+"#).unwrap(), "HTTP/HTTPS"),
            (Regex::new(r#"ftp://[^\s"'<>]+"#).unwrap(), "FTP"),
            (Regex::new(r#"wss?://[^\s"'<>]+"#).unwrap(), "WebSocket"),
            (Regex::new(r#"mqtt://[^\s"'<>]+"#).unwrap(), "MQTT"),
            (Regex::new(r#"amqp://[^\s"'<>]+"#).unwrap(), "AMQP"),
        ];

        let mut urls = Vec::new();

        for s in &strings {
            for (re, protocol) in &url_patterns {
                for mat in re.find_iter(&s.string) {
                    urls.push(UrlMatch {
                        url: mat.as_str().to_string(),
                        protocol: protocol.to_string(),
                        offset: s.offset,
                        context: s.string.clone(),
                    });
                }
            }
        }

        Ok(urls)
    }

    /// Find IP addresses
    pub async fn find_ips(&self, file_path: &Path) -> ToolResult<Vec<IpMatch>> {
        let strings = self.extract_with_offsets(file_path, 7).await?;

        let ipv4_re = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();
        let ipv6_re = Regex::new(r"(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}").unwrap();

        let mut ips = Vec::new();

        for s in &strings {
            for mat in ipv4_re.find_iter(&s.string) {
                let ip = mat.as_str();
                // Skip common non-routable addresses
                if !ip.starts_with("0.") && ip != "255.255.255.255" && ip != "127.0.0.1" {
                    ips.push(IpMatch {
                        ip: ip.to_string(),
                        ip_type: "IPv4".to_string(),
                        offset: s.offset,
                        context: s.string.clone(),
                    });
                }
            }

            for mat in ipv6_re.find_iter(&s.string) {
                ips.push(IpMatch {
                    ip: mat.as_str().to_string(),
                    ip_type: "IPv6".to_string(),
                    offset: s.offset,
                    context: s.string.clone(),
                });
            }
        }

        Ok(ips)
    }

    /// Find email addresses
    pub async fn find_emails(&self, file_path: &Path) -> ToolResult<Vec<StringWithOffset>> {
        let strings = self.extract_with_offsets(file_path, 5).await?;

        let email_re = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();

        let emails: Vec<_> = strings.into_iter()
            .filter(|s| email_re.is_match(&s.string))
            .collect();

        Ok(emails)
    }

    /// Find potential secrets/credentials
    pub async fn find_secrets(&self, file_path: &Path) -> ToolResult<Vec<SecretMatch>> {
        let strings = self.extract_with_offsets(file_path, 8).await?;

        let secret_patterns = vec![
            (r#"(?i)password\s*[:=]\s*['""]?(\S+)"#, "password"),
            (r#"(?i)passwd\s*[:=]\s*['""]?(\S+)"#, "password"),
            (r#"(?i)api[_-]?key\s*[:=]\s*['""]?([a-zA-Z0-9_-]+)"#, "api_key"),
            (r#"(?i)secret[_-]?key\s*[:=]\s*['""]?([a-zA-Z0-9_-]+)"#, "secret_key"),
            (r#"(?i)token\s*[:=]\s*['""]?([a-zA-Z0-9_.-]+)"#, "token"),
            (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key"),
            (r#"(?i)aws[_-]?access[_-]?key\s*[:=]\s*['""]?([A-Z0-9]+)"#, "aws_key"),
            (r#"(?i)aws[_-]?secret\s*[:=]\s*['""]?([a-zA-Z0-9/+=]+)"#, "aws_secret"),
            (r"ghp_[a-zA-Z0-9]{36}", "github_token"),
            (r"sk-[a-zA-Z0-9]{48}", "openai_key"),
        ];

        let mut secrets = Vec::new();

        for s in &strings {
            for (pattern, secret_type) in &secret_patterns {
                let re = Regex::new(pattern).unwrap();
                if re.is_match(&s.string) {
                    secrets.push(SecretMatch {
                        secret_type: secret_type.to_string(),
                        offset: s.offset,
                        context: s.string.clone(),
                        // Don't include actual value for security
                        redacted_value: "[REDACTED]".to_string(),
                    });
                }
            }
        }

        Ok(secrets)
    }

    /// Convert to generic findings
    pub fn to_findings(&self, result: &StringsResult) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (category, strings) in &result.categorized {
            if strings.is_empty() {
                continue;
            }

            let (finding_category, severity) = match category.as_str() {
                "urls" => (FindingCategory::Networking, FindingSeverity::Info),
                "ips" => (FindingCategory::Networking, FindingSeverity::Low),
                "credentials" => (FindingCategory::Credentials, FindingSeverity::High),
                "crypto" => (FindingCategory::Encryption, FindingSeverity::Info),
                "commands" => (FindingCategory::Executable, FindingSeverity::Low),
                "paths" => (FindingCategory::FileSystem, FindingSeverity::Info),
                "emails" => (FindingCategory::Telemetry, FindingSeverity::Low),
                _ => continue,
            };

            findings.push(Finding {
                category: finding_category,
                severity,
                title: format!("Found {} {} strings", strings.len(), category),
                description: format!("Extracted {} strings in category '{}'", strings.len(), category),
                file_path: None,
                offset: None,
                size: None,
                data: Some(serde_json::json!({
                    "category": category,
                    "count": strings.len(),
                    "samples": strings.iter().take(10).collect::<Vec<_>>(),
                })),
            });
        }

        findings
    }
}

#[async_trait]
impl ExternalTool for Strings {
    fn name(&self) -> &str {
        "strings"
    }

    async fn is_available(&self) -> bool {
        self.executable.is_some()
    }

    async fn version(&self) -> ToolResult<String> {
        let exe = self.executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("strings".to_string()))?;

        let (stdout, _, _) = run_command(
            exe.to_str().unwrap(),
            &["--version"],
            10,
        ).await?;

        Ok(stdout.lines().next().unwrap_or("unknown").to_string())
    }

    fn executable_path(&self) -> Option<&Path> {
        self.executable.as_deref()
    }
}

/// Strings extraction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringsResult {
    pub duration_ms: u64,
    pub total_count: usize,
    pub strings: Vec<String>,
    pub categorized: HashMap<String, Vec<String>>,
}

/// String with offset information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringWithOffset {
    pub offset: u64,
    pub string: String,
    pub category: StringCategory,
}

/// String categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StringCategory {
    Url,
    Ip,
    Email,
    Path,
    Command,
    Credential,
    Crypto,
    Debug,
    Error,
    Generic,
}

/// URL match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlMatch {
    pub url: String,
    pub protocol: String,
    pub offset: u64,
    pub context: String,
}

/// IP match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpMatch {
    pub ip: String,
    pub ip_type: String,
    pub offset: u64,
    pub context: String,
}

/// Secret match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub secret_type: String,
    pub offset: u64,
    pub context: String,
    pub redacted_value: String,
}

/// Pattern search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternSearchResult {
    pub matches: HashMap<String, Vec<StringWithOffset>>,
}

/// Categorize a single string
fn categorize_string(s: &str) -> StringCategory {
    let s_lower = s.to_lowercase();

    if s.contains("://") {
        StringCategory::Url
    } else if Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap().is_match(s) {
        StringCategory::Ip
    } else if s.contains('@') && s.contains('.') {
        StringCategory::Email
    } else if s.starts_with('/') || s.contains(":\\") || s.contains("./") {
        StringCategory::Path
    } else if s_lower.contains("password") || s_lower.contains("secret") || s_lower.contains("token") {
        StringCategory::Credential
    } else if s_lower.contains("aes") || s_lower.contains("sha") || s_lower.contains("rsa") || s_lower.contains("encrypt") {
        StringCategory::Crypto
    } else if s_lower.contains("debug") || s_lower.contains("verbose") || s_lower.contains("trace") {
        StringCategory::Debug
    } else if s_lower.contains("error") || s_lower.contains("fail") || s_lower.contains("exception") {
        StringCategory::Error
    } else if s_lower.starts_with("sh ") || s_lower.starts_with("bash ") || s_lower.contains("system(") {
        StringCategory::Command
    } else {
        StringCategory::Generic
    }
}

/// Categorize all strings
fn categorize_strings(strings: &[String]) -> HashMap<String, Vec<String>> {
    let mut categories: HashMap<String, Vec<String>> = HashMap::new();

    categories.insert("urls".to_string(), Vec::new());
    categories.insert("ips".to_string(), Vec::new());
    categories.insert("emails".to_string(), Vec::new());
    categories.insert("paths".to_string(), Vec::new());
    categories.insert("credentials".to_string(), Vec::new());
    categories.insert("crypto".to_string(), Vec::new());
    categories.insert("commands".to_string(), Vec::new());

    for s in strings {
        match categorize_string(s) {
            StringCategory::Url => categories.get_mut("urls").unwrap().push(s.clone()),
            StringCategory::Ip => categories.get_mut("ips").unwrap().push(s.clone()),
            StringCategory::Email => categories.get_mut("emails").unwrap().push(s.clone()),
            StringCategory::Path => categories.get_mut("paths").unwrap().push(s.clone()),
            StringCategory::Credential => categories.get_mut("credentials").unwrap().push(s.clone()),
            StringCategory::Crypto => categories.get_mut("crypto").unwrap().push(s.clone()),
            StringCategory::Command => categories.get_mut("commands").unwrap().push(s.clone()),
            _ => {}
        }
    }

    categories
}
