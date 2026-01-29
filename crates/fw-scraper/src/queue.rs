//! Download queue management with persistence and priority

use crate::{DownloadedFirmware, FirmwareMetadata, ScraperConfig, ScraperError, ScraperResult};
use serde::{Deserialize, Serialize};
use std::collections::BinaryHeap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use std::cmp::Ordering;

/// Priority levels for downloads
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadPriority {
    Critical = 4,
    High = 3,
    Normal = 2,
    Low = 1,
    Background = 0,
}

impl Default for DownloadPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Status of a queued download
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QueueItemStatus {
    Pending,
    Downloading,
    Completed,
    Failed(String),
    Retrying { attempt: u32, max_attempts: u32 },
    Cancelled,
}

/// A queued download item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItem {
    pub id: uuid::Uuid,
    pub metadata: FirmwareMetadata,
    pub priority: DownloadPriority,
    pub status: QueueItemStatus,
    pub added_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub error_message: Option<String>,
    pub local_path: Option<PathBuf>,
    pub sha256: Option<String>,
}

impl QueueItem {
    pub fn new(metadata: FirmwareMetadata, priority: DownloadPriority) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            metadata,
            priority,
            status: QueueItemStatus::Pending,
            added_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            retry_count: 0,
            max_retries: 3,
            error_message: None,
            local_path: None,
            sha256: None,
        }
    }
}

// For priority queue ordering
impl PartialEq for QueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for QueueItem {}

impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then earlier added time
        match (self.priority as u8).cmp(&(other.priority as u8)) {
            Ordering::Equal => other.added_at.cmp(&self.added_at), // Older items first
            other => other,
        }
    }
}

/// Queue statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    pub total: usize,
    pub pending: usize,
    pub downloading: usize,
    pub completed: usize,
    pub failed: usize,
    pub total_bytes_downloaded: u64,
    pub average_download_speed: f64,
}

/// Persistent download queue with priority and concurrency control
pub struct DownloadQueue {
    pending: Arc<Mutex<BinaryHeap<QueueItem>>>,
    active: Arc<Mutex<Vec<QueueItem>>>,
    completed: Arc<Mutex<Vec<QueueItem>>>,
    failed: Arc<Mutex<Vec<QueueItem>>>,
    semaphore: Arc<Semaphore>,
    config: ScraperConfig,
    client: reqwest::Client,
    persistence_path: Option<PathBuf>,
}

impl DownloadQueue {
    /// Create a new download queue
    pub fn new(config: ScraperConfig) -> ScraperResult<Self> {
        let client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()?;

        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_downloads));

        Ok(Self {
            pending: Arc::new(Mutex::new(BinaryHeap::new())),
            active: Arc::new(Mutex::new(Vec::new())),
            completed: Arc::new(Mutex::new(Vec::new())),
            failed: Arc::new(Mutex::new(Vec::new())),
            semaphore,
            config,
            client,
            persistence_path: None,
        })
    }

    /// Enable persistence to a file
    pub fn with_persistence(mut self, path: PathBuf) -> Self {
        self.persistence_path = Some(path);
        self
    }

    /// Add an item to the queue
    pub async fn enqueue(&self, metadata: FirmwareMetadata, priority: DownloadPriority) -> uuid::Uuid {
        let item = QueueItem::new(metadata, priority);
        let id = item.id;

        let mut pending = self.pending.lock().await;
        pending.push(item);

        if let Some(path) = &self.persistence_path {
            let _ = self.save_state(path).await;
        }

        id
    }

    /// Add multiple items
    pub async fn enqueue_batch(&self, items: Vec<(FirmwareMetadata, DownloadPriority)>) -> Vec<uuid::Uuid> {
        let mut pending = self.pending.lock().await;
        let mut ids = Vec::new();

        for (metadata, priority) in items {
            let item = QueueItem::new(metadata, priority);
            ids.push(item.id);
            pending.push(item);
        }

        if let Some(path) = &self.persistence_path {
            drop(pending);
            let _ = self.save_state(path).await;
        }

        ids
    }

    /// Start processing the queue
    pub async fn process(&self) -> Vec<ScraperResult<DownloadedFirmware>> {
        let mut results = Vec::new();

        loop {
            // Try to get next item
            let item = {
                let mut pending = self.pending.lock().await;
                pending.pop()
            };

            let Some(mut item) = item else {
                break;
            };

            // Acquire semaphore permit
            let permit = self.semaphore.clone().acquire_owned().await.unwrap();

            // Mark as downloading
            item.status = QueueItemStatus::Downloading;
            item.started_at = Some(chrono::Utc::now());

            {
                let mut active = self.active.lock().await;
                active.push(item.clone());
            }

            // Download
            let result = crate::downloader::download_firmware(
                &self.client,
                &item.metadata,
                &self.config,
            ).await;

            // Update status
            {
                let mut active = self.active.lock().await;
                active.retain(|i| i.id != item.id);
            }

            match result {
                Ok(downloaded) => {
                    item.status = QueueItemStatus::Completed;
                    item.completed_at = Some(chrono::Utc::now());
                    item.local_path = Some(downloaded.local_path.clone());
                    item.sha256 = Some(downloaded.sha256.clone());

                    let mut completed = self.completed.lock().await;
                    completed.push(item);

                    results.push(Ok(downloaded));
                }
                Err(e) => {
                    item.retry_count += 1;

                    if item.retry_count < item.max_retries {
                        // Re-queue for retry
                        item.status = QueueItemStatus::Retrying {
                            attempt: item.retry_count,
                            max_attempts: item.max_retries,
                        };

                        let mut pending = self.pending.lock().await;
                        pending.push(item);
                    } else {
                        // Mark as failed
                        item.status = QueueItemStatus::Failed(e.to_string());
                        item.error_message = Some(e.to_string());

                        let mut failed = self.failed.lock().await;
                        failed.push(item);

                        results.push(Err(e));
                    }
                }
            }

            drop(permit);

            // Save state periodically
            if let Some(path) = &self.persistence_path {
                let _ = self.save_state(path).await;
            }
        }

        results
    }

    /// Process queue in background, returning handle
    pub fn process_background(self: Arc<Self>) -> tokio::task::JoinHandle<Vec<ScraperResult<DownloadedFirmware>>> {
        tokio::spawn(async move {
            self.process().await
        })
    }

    /// Get queue statistics
    pub async fn stats(&self) -> QueueStats {
        let pending = self.pending.lock().await;
        let active = self.active.lock().await;
        let completed = self.completed.lock().await;
        let failed = self.failed.lock().await;

        let total_bytes: u64 = completed.iter()
            .filter_map(|i| i.metadata.file_size)
            .sum();

        QueueStats {
            total: pending.len() + active.len() + completed.len() + failed.len(),
            pending: pending.len(),
            downloading: active.len(),
            completed: completed.len(),
            failed: failed.len(),
            total_bytes_downloaded: total_bytes,
            average_download_speed: 0.0, // Would need timing data
        }
    }

    /// Cancel a pending download
    pub async fn cancel(&self, id: uuid::Uuid) -> bool {
        let mut pending = self.pending.lock().await;
        let before = pending.len();

        // Rebuild heap without the cancelled item
        let items: Vec<_> = pending.drain().filter(|i| i.id != id).collect();
        *pending = items.into_iter().collect();

        pending.len() < before
    }

    /// Get all pending items
    pub async fn pending_items(&self) -> Vec<QueueItem> {
        let pending = self.pending.lock().await;
        pending.iter().cloned().collect()
    }

    /// Get all completed items
    pub async fn completed_items(&self) -> Vec<QueueItem> {
        let completed = self.completed.lock().await;
        completed.clone()
    }

    /// Get all failed items
    pub async fn failed_items(&self) -> Vec<QueueItem> {
        let failed = self.failed.lock().await;
        failed.clone()
    }

    /// Save queue state to file
    async fn save_state(&self, path: &PathBuf) -> ScraperResult<()> {
        #[derive(Serialize)]
        struct QueueState {
            pending: Vec<QueueItem>,
            completed: Vec<QueueItem>,
            failed: Vec<QueueItem>,
        }

        let pending = self.pending.lock().await;
        let completed = self.completed.lock().await;
        let failed = self.failed.lock().await;

        let state = QueueState {
            pending: pending.iter().cloned().collect(),
            completed: completed.clone(),
            failed: failed.clone(),
        };

        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| ScraperError::Parse(e.to_string()))?;

        tokio::fs::write(path, json).await?;
        Ok(())
    }

    /// Load queue state from file
    pub async fn load_state(path: &PathBuf) -> ScraperResult<Self> {
        #[derive(Deserialize)]
        struct QueueState {
            pending: Vec<QueueItem>,
            completed: Vec<QueueItem>,
            failed: Vec<QueueItem>,
        }

        let json = tokio::fs::read_to_string(path).await?;
        let state: QueueState = serde_json::from_str(&json)
            .map_err(|e| ScraperError::Parse(e.to_string()))?;

        let config = ScraperConfig::default();
        let mut queue = Self::new(config)?;

        *queue.pending.lock().await = state.pending.into_iter().collect();
        *queue.completed.lock().await = state.completed;
        *queue.failed.lock().await = state.failed;

        queue.persistence_path = Some(path.clone());

        Ok(queue)
    }

    /// Clear completed items
    pub async fn clear_completed(&self) {
        let mut completed = self.completed.lock().await;
        completed.clear();
    }

    /// Clear failed items
    pub async fn clear_failed(&self) {
        let mut failed = self.failed.lock().await;
        failed.clear();
    }

    /// Retry all failed items
    pub async fn retry_failed(&self) {
        let mut failed = self.failed.lock().await;
        let mut pending = self.pending.lock().await;

        for mut item in failed.drain(..) {
            item.status = QueueItemStatus::Pending;
            item.retry_count = 0;
            item.error_message = None;
            pending.push(item);
        }
    }
}

/// Builder for download queue
pub struct QueueBuilder {
    config: ScraperConfig,
    persistence_path: Option<PathBuf>,
}

impl QueueBuilder {
    pub fn new() -> Self {
        Self {
            config: ScraperConfig::default(),
            persistence_path: None,
        }
    }

    pub fn config(mut self, config: ScraperConfig) -> Self {
        self.config = config;
        self
    }

    pub fn persist_to(mut self, path: PathBuf) -> Self {
        self.persistence_path = Some(path);
        self
    }

    pub fn build(self) -> ScraperResult<DownloadQueue> {
        let mut queue = DownloadQueue::new(self.config)?;
        queue.persistence_path = self.persistence_path;
        Ok(queue)
    }
}

impl Default for QueueBuilder {
    fn default() -> Self {
        Self::new()
    }
}
