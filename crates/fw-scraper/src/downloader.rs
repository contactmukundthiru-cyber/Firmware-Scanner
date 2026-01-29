//! Firmware download functionality

use crate::{DownloadedFirmware, FirmwareMetadata, ScraperConfig, ScraperError, ScraperResult};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

/// Download a firmware file with progress tracking
pub async fn download_firmware(
    client: &reqwest::Client,
    metadata: &FirmwareMetadata,
    config: &ScraperConfig,
) -> ScraperResult<DownloadedFirmware> {
    tracing::info!("Downloading: {} from {}", metadata.filename, metadata.url);

    // Create download directory
    tokio::fs::create_dir_all(&config.download_dir).await?;

    // Build local path
    let local_path = config.download_dir.join(&metadata.filename);

    // Check if file already exists with correct hash
    if local_path.exists() {
        if let Some(expected_hash) = &metadata.checksum {
            let existing_hash = hash_file(&local_path).await?;
            if existing_hash.to_lowercase() == expected_hash.to_lowercase() {
                tracing::info!("File already exists with correct hash: {}", metadata.filename);
                return Ok(DownloadedFirmware {
                    metadata: metadata.clone(),
                    local_path,
                    sha256: existing_hash,
                    downloaded_at: chrono::Utc::now(),
                });
            }
        }
    }

    // Start download
    let response = client.get(&metadata.url).send().await?;

    if !response.status().is_success() {
        return Err(ScraperError::Http(
            response.error_for_status().unwrap_err(),
        ));
    }

    // Check content length
    if let Some(content_length) = response.content_length() {
        if content_length > config.max_file_size {
            return Err(ScraperError::Parse(format!(
                "File too large: {} bytes (max: {})",
                content_length, config.max_file_size
            )));
        }
    }

    // Download with streaming and hashing
    let mut file = tokio::fs::File::create(&local_path).await?;
    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        downloaded += chunk.len() as u64;

        // Check size limit during download
        if downloaded > config.max_file_size {
            drop(file);
            tokio::fs::remove_file(&local_path).await?;
            return Err(ScraperError::Parse(format!(
                "Download exceeded max size: {} bytes",
                config.max_file_size
            )));
        }

        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }

    file.flush().await?;

    let sha256 = hex::encode(hasher.finalize());

    // Verify checksum if provided
    if let Some(expected_hash) = &metadata.checksum {
        if sha256.to_lowercase() != expected_hash.to_lowercase() {
            tracing::warn!(
                "Checksum mismatch for {}: expected {}, got {}",
                metadata.filename,
                expected_hash,
                sha256
            );
        }
    }

    tracing::info!(
        "Downloaded {} ({} bytes, SHA256: {})",
        metadata.filename,
        downloaded,
        sha256
    );

    Ok(DownloadedFirmware {
        metadata: metadata.clone(),
        local_path,
        sha256,
        downloaded_at: chrono::Utc::now(),
    })
}

/// Hash an existing file
async fn hash_file(path: &PathBuf) -> ScraperResult<String> {
    let data = tokio::fs::read(path).await?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

/// Batch download multiple firmware files
pub async fn batch_download(
    client: &reqwest::Client,
    firmwares: &[FirmwareMetadata],
    config: &ScraperConfig,
) -> Vec<ScraperResult<DownloadedFirmware>> {
    use futures::stream::FuturesUnordered;

    let mut futures = FuturesUnordered::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
        config.max_concurrent_downloads,
    ));

    for metadata in firmwares {
        let client = client.clone();
        let metadata = metadata.clone();
        let config = config.clone();
        let semaphore = semaphore.clone();

        futures.push(async move {
            let _permit = semaphore.acquire().await.unwrap();
            download_firmware(&client, &metadata, &config).await
        });
    }

    let mut results = Vec::new();
    while let Some(result) = futures.next().await {
        results.push(result);
    }

    results
}
