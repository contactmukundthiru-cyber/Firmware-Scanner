//! Pre-configured firmware sources for automated scraping

use crate::{FirmwareMetadata, FirmwareSource, ScraperConfig, ScraperResult, ScraperError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trait for firmware source providers
#[async_trait]
pub trait FirmwareSourceProvider: Send + Sync {
    /// Get the source name
    fn name(&self) -> &str;

    /// Discover firmware from this source
    async fn discover(
        &self,
        client: &reqwest::Client,
        config: &ScraperConfig,
    ) -> ScraperResult<Vec<FirmwareMetadata>>;

    /// Check if this source is available
    async fn is_available(&self, client: &reqwest::Client) -> bool;
}

/// GitHub releases source
pub struct GitHubReleaseSource {
    pub owner: String,
    pub repo: String,
    pub asset_patterns: Vec<String>,
}

#[async_trait]
impl FirmwareSourceProvider for GitHubReleaseSource {
    fn name(&self) -> &str {
        "GitHub Releases"
    }

    async fn discover(
        &self,
        client: &reqwest::Client,
        _config: &ScraperConfig,
    ) -> ScraperResult<Vec<FirmwareMetadata>> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/releases",
            self.owner, self.repo
        );

        let response = client
            .get(&url)
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ScraperError::Parse(format!(
                "GitHub API error: {}",
                response.status()
            )));
        }

        let releases: Vec<GitHubRelease> = response.json().await?;
        let mut firmwares = Vec::new();

        for release in releases {
            for asset in release.assets {
                // Check if asset matches any pattern
                let matches = self.asset_patterns.is_empty() ||
                    self.asset_patterns.iter().any(|p| {
                        asset.name.contains(p) ||
                        regex::Regex::new(p).map(|r| r.is_match(&asset.name)).unwrap_or(false)
                    });

                if matches {
                    firmwares.push(FirmwareMetadata {
                        url: asset.browser_download_url,
                        filename: asset.name,
                        vendor: Some(self.owner.clone()),
                        product: Some(self.repo.clone()),
                        version: Some(release.tag_name.clone()),
                        release_date: Some(release.published_at.clone()),
                        file_size: Some(asset.size),
                        checksum: None,
                        source: FirmwareSource::GitHubRelease {
                            owner: self.owner.clone(),
                            repo: self.repo.clone(),
                        },
                        discovered_at: chrono::Utc::now(),
                    });
                }
            }
        }

        Ok(firmwares)
    }

    async fn is_available(&self, client: &reqwest::Client) -> bool {
        let url = format!(
            "https://api.github.com/repos/{}/{}",
            self.owner, self.repo
        );
        client.head(&url).send().await.map(|r| r.status().is_success()).unwrap_or(false)
    }
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    published_at: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// FTP firmware source
pub struct FtpSource {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[async_trait]
impl FirmwareSourceProvider for FtpSource {
    fn name(&self) -> &str {
        "FTP Server"
    }

    async fn discover(
        &self,
        _client: &reqwest::Client,
        config: &ScraperConfig,
    ) -> ScraperResult<Vec<FirmwareMetadata>> {
        // FTP discovery using suppaftp or similar
        // For now, return empty - would need FTP client implementation
        tracing::info!("FTP source discovery not fully implemented yet");
        Ok(Vec::new())
    }

    async fn is_available(&self, _client: &reqwest::Client) -> bool {
        // Would need TCP connection check
        true
    }
}

/// Vendor-specific firmware page source
pub struct VendorPageSource {
    pub name: String,
    pub base_url: String,
    pub firmware_page_patterns: Vec<String>,
    pub download_link_patterns: Vec<String>,
}

#[async_trait]
impl FirmwareSourceProvider for VendorPageSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn discover(
        &self,
        client: &reqwest::Client,
        config: &ScraperConfig,
    ) -> ScraperResult<Vec<FirmwareMetadata>> {
        crate::discovery::discover_firmware_links(client, &self.base_url, config).await
    }

    async fn is_available(&self, client: &reqwest::Client) -> bool {
        client.head(&self.base_url).send().await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

/// Well-known firmware sources registry
#[derive(Default)]
pub struct SourceRegistry {
    sources: HashMap<String, Box<dyn FirmwareSourceProvider>>,
}

impl SourceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add built-in popular sources
    pub fn with_defaults(mut self) -> Self {
        // OpenWRT
        self.register("openwrt", Box::new(GitHubReleaseSource {
            owner: "openwrt".to_string(),
            repo: "openwrt".to_string(),
            asset_patterns: vec![r"\.bin$".to_string(), r"\.img$".to_string()],
        }));

        // DD-WRT (via their site)
        self.register("ddwrt", Box::new(VendorPageSource {
            name: "DD-WRT".to_string(),
            base_url: "https://dd-wrt.com/support/router-database/".to_string(),
            firmware_page_patterns: vec![r"/support/".to_string()],
            download_link_patterns: vec![r"\.bin$".to_string()],
        }));

        // Tasmota
        self.register("tasmota", Box::new(GitHubReleaseSource {
            owner: "arendst".to_string(),
            repo: "Tasmota".to_string(),
            asset_patterns: vec![r"\.bin$".to_string(), r"tasmota".to_string()],
        }));

        // ESPHome
        self.register("esphome", Box::new(GitHubReleaseSource {
            owner: "esphome".to_string(),
            repo: "esphome".to_string(),
            asset_patterns: vec![],
        }));

        // Marlin 3D printer firmware
        self.register("marlin", Box::new(GitHubReleaseSource {
            owner: "MarlinFirmware".to_string(),
            repo: "Marlin".to_string(),
            asset_patterns: vec![r"\.bin$".to_string(), r"\.hex$".to_string()],
        }));

        // micropython
        self.register("micropython", Box::new(GitHubReleaseSource {
            owner: "micropython".to_string(),
            repo: "micropython".to_string(),
            asset_patterns: vec![r"\.bin$".to_string(), r"\.uf2$".to_string()],
        }));

        self
    }

    /// Register a new source
    pub fn register(&mut self, id: &str, source: Box<dyn FirmwareSourceProvider>) {
        self.sources.insert(id.to_string(), source);
    }

    /// Get a source by ID
    pub fn get(&self, id: &str) -> Option<&dyn FirmwareSourceProvider> {
        self.sources.get(id).map(|s| s.as_ref())
    }

    /// List all registered sources
    pub fn list(&self) -> Vec<&str> {
        self.sources.keys().map(|s| s.as_str()).collect()
    }

    /// Discover from all sources
    pub async fn discover_all(
        &self,
        client: &reqwest::Client,
        config: &ScraperConfig,
    ) -> Vec<(String, ScraperResult<Vec<FirmwareMetadata>>)> {
        let mut results = Vec::new();

        for (id, source) in &self.sources {
            tracing::info!("Discovering from source: {}", source.name());
            let result = source.discover(client, config).await;
            results.push((id.clone(), result));
        }

        results
    }
}

/// Predefined vendor configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorConfig {
    pub name: String,
    pub homepage: String,
    pub firmware_urls: Vec<String>,
    pub link_patterns: Vec<String>,
    pub version_regex: Option<String>,
}

/// Load vendor configurations from TOML
pub fn load_vendor_configs(toml_content: &str) -> Result<Vec<VendorConfig>, toml::de::Error> {
    #[derive(Deserialize)]
    struct VendorConfigs {
        vendors: Vec<VendorConfig>,
    }

    let configs: VendorConfigs = toml::from_str(toml_content)?;
    Ok(configs.vendors)
}

/// Built-in vendor configurations
pub fn builtin_vendors() -> Vec<VendorConfig> {
    vec![
        VendorConfig {
            name: "TP-Link".to_string(),
            homepage: "https://www.tp-link.com".to_string(),
            firmware_urls: vec![
                "https://www.tp-link.com/us/support/download/".to_string(),
            ],
            link_patterns: vec![
                r"firmware.*\.zip$".to_string(),
                r"firmware.*\.bin$".to_string(),
            ],
            version_regex: Some(r"V(\d+\.\d+\.\d+)".to_string()),
        },
        VendorConfig {
            name: "Netgear".to_string(),
            homepage: "https://www.netgear.com".to_string(),
            firmware_urls: vec![
                "https://www.netgear.com/support/download/".to_string(),
            ],
            link_patterns: vec![
                r"\.zip$".to_string(),
                r"\.img$".to_string(),
                r"\.chk$".to_string(),
            ],
            version_regex: Some(r"V(\d+\.\d+\.\d+\.\d+)".to_string()),
        },
        VendorConfig {
            name: "ASUS".to_string(),
            homepage: "https://www.asus.com".to_string(),
            firmware_urls: vec![
                "https://www.asus.com/support/download-center/".to_string(),
            ],
            link_patterns: vec![
                r"firmware.*\.zip$".to_string(),
                r"\.trx$".to_string(),
            ],
            version_regex: Some(r"(\d+\.\d+\.\d+\.\d+)".to_string()),
        },
        VendorConfig {
            name: "D-Link".to_string(),
            homepage: "https://www.dlink.com".to_string(),
            firmware_urls: vec![
                "https://support.dlink.com/".to_string(),
            ],
            link_patterns: vec![
                r"firmware.*\.bin$".to_string(),
                r"\.zip$".to_string(),
            ],
            version_regex: Some(r"v?(\d+\.\d+)".to_string()),
        },
        VendorConfig {
            name: "Linksys".to_string(),
            homepage: "https://www.linksys.com".to_string(),
            firmware_urls: vec![
                "https://www.linksys.com/support/".to_string(),
            ],
            link_patterns: vec![
                r"\.bin$".to_string(),
                r"\.img$".to_string(),
            ],
            version_regex: Some(r"(\d+\.\d+\.\d+)".to_string()),
        },
    ]
}
