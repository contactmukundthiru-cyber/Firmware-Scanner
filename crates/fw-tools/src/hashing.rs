//! Hashing utilities including fuzzy hashing (ssdeep/tlsh)
//!
//! Supports multiple hash algorithms for file identification and similarity detection.

use crate::{
    ExternalTool, ToolConfig, ToolError, ToolResult, run_command,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512, Digest};
use std::path::{Path, PathBuf};

/// Hash calculator (mostly pure Rust, with optional ssdeep/tlsh)
pub struct HashCalculator {
    config: ToolConfig,
    ssdeep_executable: Option<PathBuf>,
    tlsh_executable: Option<PathBuf>,
}

impl HashCalculator {
    pub fn new(config: ToolConfig) -> Self {
        let ssdeep_executable = config.tool_paths.get("ssdeep")
            .cloned()
            .or_else(|| crate::get_command_path("ssdeep"));

        let tlsh_executable = config.tool_paths.get("tlsh")
            .cloned()
            .or_else(|| crate::get_command_path("tlsh"));

        Self {
            config,
            ssdeep_executable,
            tlsh_executable,
        }
    }

    /// Calculate all hashes for a file
    pub async fn hash_file(&self, file_path: &Path) -> ToolResult<FileHashes> {
        let data = tokio::fs::read(file_path).await?;

        let md5 = format!("{:x}", md5::compute(&data));

        let mut sha1_hasher = sha1::Sha1::new();
        sha1_hasher.update(&data);
        let sha1 = format!("{:x}", sha1_hasher.finalize());

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&data);
        let sha256 = format!("{:x}", sha256_hasher.finalize());

        let mut sha512_hasher = Sha512::new();
        sha512_hasher.update(&data);
        let sha512 = format!("{:x}", sha512_hasher.finalize());

        // Calculate CRC32
        let crc32 = crc32fast::hash(&data);

        // Try ssdeep if available
        let ssdeep = if self.ssdeep_executable.is_some() {
            self.ssdeep(file_path).await.ok()
        } else {
            None
        };

        // Try tlsh if available
        let tlsh = if self.tlsh_executable.is_some() {
            self.tlsh(file_path).await.ok()
        } else {
            None
        };

        Ok(FileHashes {
            file_path: file_path.to_path_buf(),
            file_size: data.len() as u64,
            md5,
            sha1,
            sha256,
            sha512,
            crc32: format!("{:08X}", crc32),
            ssdeep,
            tlsh,
        })
    }

    /// Calculate ssdeep fuzzy hash
    pub async fn ssdeep(&self, file_path: &Path) -> ToolResult<String> {
        let exe = self.ssdeep_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("ssdeep".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-b", file_path.to_str().unwrap()],
            60,
        ).await?;

        // ssdeep output: "hash,filename"
        Ok(stdout.split(',').next().unwrap_or("").trim().to_string())
    }

    /// Calculate TLSH hash
    pub async fn tlsh(&self, file_path: &Path) -> ToolResult<String> {
        let exe = self.tlsh_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("tlsh".to_string()))?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &["-f", file_path.to_str().unwrap()],
            60,
        ).await?;

        // TLSH output format varies
        Ok(stdout.split_whitespace().next().unwrap_or("").to_string())
    }

    /// Compare two ssdeep hashes
    pub async fn ssdeep_compare(&self, hash1: &str, hash2: &str) -> ToolResult<i32> {
        let exe = self.ssdeep_executable.as_ref()
            .ok_or_else(|| ToolError::NotFound("ssdeep".to_string()))?;

        // Create temp files with hashes
        let temp_dir = tempfile::tempdir()?;
        let file1 = temp_dir.path().join("hash1.txt");
        let file2 = temp_dir.path().join("hash2.txt");

        tokio::fs::write(&file1, format!("{},file1", hash1)).await?;
        tokio::fs::write(&file2, format!("{},file2", hash2)).await?;

        let (stdout, _stderr, _code) = run_command(
            exe.to_str().unwrap(),
            &[
                "-p",
                file1.to_str().unwrap(),
                file2.to_str().unwrap(),
            ],
            60,
        ).await?;

        // Parse similarity score from output
        let score = stdout.lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    parts.first().and_then(|s| s.trim_matches(|c| c == '(' || c == ')').parse().ok())
                } else {
                    None
                }
            })
            .next()
            .unwrap_or(0);

        Ok(score)
    }

    /// Hash data directly
    pub fn hash_bytes(&self, data: &[u8]) -> ByteHashes {
        let md5 = format!("{:x}", md5::compute(data));

        let mut sha1_hasher = sha1::Sha1::new();
        sha1_hasher.update(data);
        let sha1 = format!("{:x}", sha1_hasher.finalize());

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(data);
        let sha256 = format!("{:x}", sha256_hasher.finalize());

        let crc32 = crc32fast::hash(data);

        ByteHashes {
            size: data.len(),
            md5,
            sha1,
            sha256,
            crc32: format!("{:08X}", crc32),
        }
    }
}

#[async_trait]
impl ExternalTool for HashCalculator {
    fn name(&self) -> &str {
        "hash-calculator"
    }

    async fn is_available(&self) -> bool {
        true // Core hashing is always available
    }

    async fn version(&self) -> ToolResult<String> {
        Ok("built-in".to_string())
    }

    fn executable_path(&self) -> Option<&Path> {
        None
    }
}

/// File hash results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub crc32: String,
    pub ssdeep: Option<String>,
    pub tlsh: Option<String>,
}

/// Byte hash results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteHashes {
    pub size: usize,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub crc32: String,
}

/// Hash comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashComparison {
    pub file1: String,
    pub file2: String,
    pub sha256_match: bool,
    pub ssdeep_similarity: Option<i32>,
    pub tlsh_distance: Option<i32>,
}

impl FileHashes {
    /// Format as markdown
    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("**File:** {}\n", self.file_path.display()));
        s.push_str(&format!("**Size:** {} bytes\n\n", self.file_size));
        s.push_str("| Algorithm | Hash |\n");
        s.push_str("|-----------|------|\n");
        s.push_str(&format!("| MD5 | `{}` |\n", self.md5));
        s.push_str(&format!("| SHA1 | `{}` |\n", self.sha1));
        s.push_str(&format!("| SHA256 | `{}` |\n", self.sha256));
        s.push_str(&format!("| SHA512 | `{}` |\n", self.sha512));
        s.push_str(&format!("| CRC32 | `{}` |\n", self.crc32));

        if let Some(ref ssdeep) = self.ssdeep {
            s.push_str(&format!("| ssdeep | `{}` |\n", ssdeep));
        }
        if let Some(ref tlsh) = self.tlsh {
            s.push_str(&format!("| TLSH | `{}` |\n", tlsh));
        }

        s
    }

    /// Check if hashes match another file
    pub fn matches(&self, other: &FileHashes) -> bool {
        self.sha256 == other.sha256
    }
}
