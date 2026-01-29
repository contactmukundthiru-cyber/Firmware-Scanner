//! Firmware Scraper - Automated firmware discovery and download
//!
//! This module provides capabilities to automatically discover and download
//! firmware images from various sources for analysis.

pub mod sources;
pub mod downloader;
pub mod discovery;
pub mod queue;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScraperError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Rate limited")]
    RateLimited,

    #[error("Blocked by robots.txt")]
    RobotsBlocked,

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
}

pub type ScraperResult<T> = Result<T, ScraperError>;

/// Discovered firmware metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareMetadata {
    pub url: String,
    pub filename: String,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub release_date: Option<String>,
    pub file_size: Option<u64>,
    pub checksum: Option<String>,
    pub source: FirmwareSource,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
}

/// Source of firmware discovery
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirmwareSource {
    VendorWebsite(String),
    FtpServer(String),
    GitHubRelease { owner: String, repo: String },
    FirmwareRepository(String),
    DirectLink,
    Custom(String),
}

/// Downloaded firmware artifact
#[derive(Debug, Clone)]
pub struct DownloadedFirmware {
    pub metadata: FirmwareMetadata,
    pub local_path: PathBuf,
    pub sha256: String,
    pub downloaded_at: chrono::DateTime<chrono::Utc>,
}

/// Configuration for the scraper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScraperConfig {
    /// Maximum concurrent downloads
    pub max_concurrent_downloads: usize,

    /// Download directory
    pub download_dir: PathBuf,

    /// Respect robots.txt
    pub respect_robots_txt: bool,

    /// Rate limit (requests per second)
    pub rate_limit_rps: f64,

    /// User agent string
    pub user_agent: String,

    /// Maximum file size to download (bytes)
    pub max_file_size: u64,

    /// File extensions to download
    pub allowed_extensions: Vec<String>,

    /// Request timeout (seconds)
    pub timeout_secs: u64,
}

impl Default for ScraperConfig {
    fn default() -> Self {
        Self {
            max_concurrent_downloads: 4,
            download_dir: PathBuf::from("./downloads"),
            respect_robots_txt: true,
            rate_limit_rps: 2.0,
            user_agent: "FirmwareScanner/1.0 (Security Research)".to_string(),
            max_file_size: 2 * 1024 * 1024 * 1024, // 2GB
            allowed_extensions: vec![
                "bin".to_string(),
                "img".to_string(),
                "fw".to_string(),
                "rom".to_string(),
                "zip".to_string(),
                "tar".to_string(),
                "gz".to_string(),
                "bz2".to_string(),
                "xz".to_string(),
                "ubi".to_string(),
                "squashfs".to_string(),
                "cramfs".to_string(),
                "jffs2".to_string(),
                "elf".to_string(),
                "exe".to_string(),
                "dll".to_string(),
                "so".to_string(),
                "dylib".to_string(),
            ],
            timeout_secs: 300,
        }
    }
}

/// Main scraper interface
pub struct FirmwareScraper {
    config: ScraperConfig,
    client: reqwest::Client,
}

impl FirmwareScraper {
    pub fn new(config: ScraperConfig) -> ScraperResult<Self> {
        let client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()?;

        Ok(Self { config, client })
    }

    /// Discover firmware from a vendor website
    pub async fn discover_from_url(&self, url: &str) -> ScraperResult<Vec<FirmwareMetadata>> {
        discovery::discover_firmware_links(&self.client, url, &self.config).await
    }

    /// Download a firmware file
    pub async fn download(&self, metadata: &FirmwareMetadata) -> ScraperResult<DownloadedFirmware> {
        downloader::download_firmware(&self.client, metadata, &self.config).await
    }

    /// Discover and download from multiple sources
    pub async fn scrape_sources(&self, urls: &[String]) -> Vec<ScraperResult<DownloadedFirmware>> {
        let mut results = Vec::new();

        for url in urls {
            match self.discover_from_url(url).await {
                Ok(firmwares) => {
                    for fw in firmwares {
                        results.push(self.download(&fw).await);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to discover from {}: {}", url, e);
                }
            }
        }

        results
    }
}
