//! Firmware discovery from web sources

use crate::{FirmwareMetadata, FirmwareSource, ScraperConfig, ScraperError, ScraperResult};
use regex::Regex;
use scraper::{Html, Selector};
use url::Url;

/// Firmware file extensions to look for
const FIRMWARE_EXTENSIONS: &[&str] = &[
    ".bin", ".img", ".fw", ".rom", ".ubi", ".squashfs", ".cramfs", ".jffs2",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".elf", ".exe", ".dll", ".so", ".dylib",
    ".trx", ".chk", ".rmt", ".pkg", ".ipk", ".apk",
];

/// Common firmware download page patterns
const DOWNLOAD_PATTERNS: &[&str] = &[
    r"download", r"firmware", r"driver", r"software", r"update",
    r"release", r"support", r"file", r"bios",
];

/// Discover firmware links from a webpage
pub async fn discover_firmware_links(
    client: &reqwest::Client,
    url: &str,
    config: &ScraperConfig,
) -> ScraperResult<Vec<FirmwareMetadata>> {
    let base_url = Url::parse(url).map_err(|e| ScraperError::InvalidUrl(e.to_string()))?;

    // Fetch the page
    let response = client.get(url).send().await?;
    let html = response.text().await?;

    let document = Html::parse_document(&html);
    let mut firmwares = Vec::new();

    // Find all links
    let link_selector = Selector::parse("a[href]").unwrap();

    for element in document.select(&link_selector) {
        if let Some(href) = element.value().attr("href") {
            // Resolve relative URLs
            let full_url = match base_url.join(href) {
                Ok(u) => u,
                Err(_) => continue,
            };

            let url_str = full_url.as_str();
            let filename = full_url
                .path_segments()
                .and_then(|s| s.last())
                .unwrap_or("")
                .to_string();

            // Check if it looks like firmware
            if is_firmware_link(url_str, &filename) {
                let link_text = element.text().collect::<String>();

                // Try to extract version from filename or link text
                let version = extract_version(&filename).or_else(|| extract_version(&link_text));

                // Get vendor from domain
                let vendor = base_url.host_str().map(|h| {
                    h.split('.')
                        .rev()
                        .nth(1)
                        .unwrap_or(h)
                        .to_string()
                });

                firmwares.push(FirmwareMetadata {
                    url: url_str.to_string(),
                    filename: filename.clone(),
                    vendor,
                    product: extract_product(&filename, &link_text),
                    version,
                    release_date: None,
                    file_size: None,
                    checksum: None,
                    source: FirmwareSource::VendorWebsite(base_url.host_str().unwrap_or("").to_string()),
                    discovered_at: chrono::Utc::now(),
                });
            }
        }
    }

    // Also check for JavaScript-based download links
    firmwares.extend(extract_js_download_links(&html, &base_url)?);

    // Deduplicate by URL
    firmwares.sort_by(|a, b| a.url.cmp(&b.url));
    firmwares.dedup_by(|a, b| a.url == b.url);

    Ok(firmwares)
}

fn is_firmware_link(url: &str, filename: &str) -> bool {
    let lower_url = url.to_lowercase();
    let lower_filename = filename.to_lowercase();

    // Check extensions
    for ext in FIRMWARE_EXTENSIONS {
        if lower_filename.ends_with(ext) || lower_url.ends_with(ext) {
            return true;
        }
    }

    // Check for firmware-related keywords in URL
    for pattern in DOWNLOAD_PATTERNS {
        if lower_url.contains(pattern) {
            // Must also have a file-like extension
            if lower_filename.contains('.') {
                return true;
            }
        }
    }

    false
}

fn extract_version(text: &str) -> Option<String> {
    // Common version patterns
    let patterns = [
        r"v?(\d+\.\d+\.\d+(?:\.\d+)?)",
        r"v?(\d+\.\d+)",
        r"[_-](\d{4}\d{2}\d{2})[_-]", // Date-based versions
        r"[_-]([a-zA-Z]?\d+\.\d+[a-zA-Z]?\d*)[_-\.]",
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(text) {
                if let Some(version) = caps.get(1) {
                    return Some(version.as_str().to_string());
                }
            }
        }
    }

    None
}

fn extract_product(filename: &str, link_text: &str) -> Option<String> {
    // Remove version and extension from filename
    let mut product = filename.to_string();

    // Remove common extensions
    for ext in FIRMWARE_EXTENSIONS {
        if product.to_lowercase().ends_with(ext) {
            product = product[..product.len() - ext.len()].to_string();
        }
    }

    // Remove version numbers
    if let Ok(re) = Regex::new(r"[_-]?v?\d+[\.\d]*[_-]?") {
        product = re.replace_all(&product, " ").to_string();
    }

    // Clean up
    product = product
        .replace('_', " ")
        .replace('-', " ")
        .trim()
        .to_string();

    if !product.is_empty() {
        Some(product)
    } else if !link_text.trim().is_empty() {
        Some(link_text.trim().to_string())
    } else {
        None
    }
}

fn extract_js_download_links(html: &str, base_url: &Url) -> ScraperResult<Vec<FirmwareMetadata>> {
    let mut firmwares = Vec::new();

    // Look for URLs in JavaScript
    let url_pattern = Regex::new(r#"["']((https?://[^"']+\.(bin|img|fw|zip|tar|gz))[^"']*)["']"#)
        .map_err(|e| ScraperError::Parse(e.to_string()))?;

    for cap in url_pattern.captures_iter(html) {
        if let Some(url_match) = cap.get(1) {
            let url_str = url_match.as_str();
            if let Ok(full_url) = Url::parse(url_str).or_else(|_| base_url.join(url_str)) {
                let filename = full_url
                    .path_segments()
                    .and_then(|s| s.last())
                    .unwrap_or("")
                    .to_string();

                if is_firmware_link(full_url.as_str(), &filename) {
                    firmwares.push(FirmwareMetadata {
                        url: full_url.to_string(),
                        filename,
                        vendor: base_url.host_str().map(|h| h.to_string()),
                        product: None,
                        version: extract_version(full_url.as_str()),
                        release_date: None,
                        file_size: None,
                        checksum: None,
                        source: FirmwareSource::VendorWebsite(
                            base_url.host_str().unwrap_or("").to_string(),
                        ),
                        discovered_at: chrono::Utc::now(),
                    });
                }
            }
        }
    }

    Ok(firmwares)
}

/// Discover firmware from GitHub releases
pub async fn discover_github_releases(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
) -> ScraperResult<Vec<FirmwareMetadata>> {
    let api_url = format!("https://api.github.com/repos/{}/{}/releases", owner, repo);

    let response = client
        .get(&api_url)
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await?;

    if !response.status().is_success() {
        return Ok(Vec::new());
    }

    let releases: Vec<serde_json::Value> = response.json().await?;
    let mut firmwares = Vec::new();

    for release in releases {
        let version = release["tag_name"].as_str().map(|s| s.to_string());
        let release_date = release["published_at"].as_str().map(|s| s.to_string());

        if let Some(assets) = release["assets"].as_array() {
            for asset in assets {
                if let (Some(name), Some(url), Some(size)) = (
                    asset["name"].as_str(),
                    asset["browser_download_url"].as_str(),
                    asset["size"].as_u64(),
                ) {
                    if is_firmware_link(url, name) {
                        firmwares.push(FirmwareMetadata {
                            url: url.to_string(),
                            filename: name.to_string(),
                            vendor: Some(owner.to_string()),
                            product: Some(repo.to_string()),
                            version: version.clone(),
                            release_date: release_date.clone(),
                            file_size: Some(size),
                            checksum: None,
                            source: FirmwareSource::GitHubRelease {
                                owner: owner.to_string(),
                                repo: repo.to_string(),
                            },
                            discovered_at: chrono::Utc::now(),
                        });
                    }
                }
            }
        }
    }

    Ok(firmwares)
}

/// Discover firmware from FTP servers
pub async fn discover_ftp_directory(
    client: &reqwest::Client,
    ftp_url: &str,
) -> ScraperResult<Vec<FirmwareMetadata>> {
    // For HTTP-based FTP directory listings
    let response = client.get(ftp_url).send().await?;
    let html = response.text().await?;

    let base_url = Url::parse(ftp_url).map_err(|e| ScraperError::InvalidUrl(e.to_string()))?;
    let document = Html::parse_document(&html);
    let mut firmwares = Vec::new();

    // FTP listings often use <a> tags or <pre> formatted text
    let link_selector = Selector::parse("a[href]").unwrap();

    for element in document.select(&link_selector) {
        if let Some(href) = element.value().attr("href") {
            if let Ok(full_url) = base_url.join(href) {
                let filename = full_url
                    .path_segments()
                    .and_then(|s| s.last())
                    .unwrap_or("")
                    .to_string();

                if is_firmware_link(full_url.as_str(), &filename) {
                    firmwares.push(FirmwareMetadata {
                        url: full_url.to_string(),
                        filename: filename.clone(),
                        vendor: base_url.host_str().map(|h| h.to_string()),
                        product: extract_product(&filename, ""),
                        version: extract_version(&filename),
                        release_date: None,
                        file_size: None,
                        checksum: None,
                        source: FirmwareSource::FtpServer(
                            base_url.host_str().unwrap_or("").to_string(),
                        ),
                        discovered_at: chrono::Utc::now(),
                    });
                }
            }
        }
    }

    Ok(firmwares)
}
