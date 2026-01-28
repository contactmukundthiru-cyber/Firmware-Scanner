//! Firmware ingestion and normalization layer
//!
//! Handles container identification, filesystem extraction, and architecture detection.

mod arch;
mod container;
mod filesystem;

pub use arch::{ArchitectureDetector, ArchitectureInfo, CpuArchitecture, Endianness, OsFingerprint};
pub use container::{ContainerInfo, ContainerType};
pub use filesystem::{ExtractedFile, ExtractedFilesystem, FileType};

use crate::{CoreError, CoreResult};
use chrono::{DateTime, Utc};
use fw_parsers::magic;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents an analyzed firmware artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareArtifact {
    /// Unique identifier
    pub id: Uuid,
    /// Original source name/path
    pub source_name: Option<String>,
    /// SHA-256 hash of the entire artifact
    pub hash: String,
    /// Size in bytes
    pub size: u64,
    /// Ingestion timestamp
    pub timestamp: DateTime<Utc>,
    /// Detected container type
    pub container_type: ContainerType,
    /// Nested containers found
    pub nested_containers: Vec<ContainerInfo>,
    /// Extracted filesystems
    pub filesystems: Vec<ExtractedFilesystem>,
    /// Architecture information
    pub architecture: Option<ArchitectureInfo>,
    /// All extracted files (flattened)
    pub files: Vec<ExtractedFile>,
    /// Metadata
    pub metadata: HashMap<String, String>,
    /// Entropy (for encryption detection)
    pub entropy: f64,
    /// Is potentially encrypted
    pub is_encrypted: bool,
}

impl FirmwareArtifact {
    /// Get total number of files
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Get files by type
    pub fn files_by_type(&self, file_type: FileType) -> Vec<&ExtractedFile> {
        self.files.iter().filter(|f| f.file_type == file_type).collect()
    }

    /// Get all executable files
    pub fn executables(&self) -> Vec<&ExtractedFile> {
        self.files
            .iter()
            .filter(|f| matches!(f.file_type, FileType::Elf | FileType::Pe | FileType::MachO | FileType::Script))
            .collect()
    }

    /// Get all configuration files
    pub fn config_files(&self) -> Vec<&ExtractedFile> {
        self.files
            .iter()
            .filter(|f| {
                f.file_type == FileType::Config
                    || f.path.ends_with(".conf")
                    || f.path.ends_with(".cfg")
                    || f.path.ends_with(".ini")
                    || f.path.ends_with(".json")
                    || f.path.ends_with(".xml")
                    || f.path.ends_with(".yaml")
                    || f.path.ends_with(".yml")
            })
            .collect()
    }

    /// Find file by path
    pub fn find_file(&self, path: &str) -> Option<&ExtractedFile> {
        self.files.iter().find(|f| f.path == path || f.path.ends_with(path))
    }

    /// Get file data by path
    pub fn get_file_data(&self, path: &str) -> Option<&[u8]> {
        self.find_file(path).and_then(|f| f.data.as_deref())
    }
}

/// Firmware ingester
pub struct Ingester {
    max_recursion_depth: usize,
    arch_detector: ArchitectureDetector,
}

impl Ingester {
    pub fn new(max_recursion_depth: usize) -> Self {
        Self {
            max_recursion_depth,
            arch_detector: ArchitectureDetector::new(),
        }
    }

    /// Ingest firmware from raw bytes
    pub fn ingest(&self, data: &[u8], source_name: Option<String>) -> CoreResult<FirmwareArtifact> {
        let id = Uuid::new_v4();
        let timestamp = Utc::now();

        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());

        // Calculate entropy
        let entropy = magic::calculate_entropy(data);
        let is_encrypted = entropy > 7.9;

        // Detect primary container type
        let container_type = self.detect_container_type(data);

        // Find nested containers
        let nested_containers = self.find_nested_containers(data, 0)?;

        // Extract filesystems
        let filesystems = self.extract_filesystems(data, &nested_containers)?;

        // Extract all files
        let files = self.extract_all_files(data, &filesystems, &nested_containers)?;

        // Detect architecture from executables
        let architecture = self.detect_architecture(&files);

        // Collect metadata
        let mut metadata = HashMap::new();
        metadata.insert("entropy".to_string(), format!("{:.4}", entropy));
        metadata.insert("container_type".to_string(), format!("{:?}", container_type));
        if let Some(ref arch) = architecture {
            metadata.insert("architecture".to_string(), format!("{:?}", arch.cpu));
            metadata.insert("endianness".to_string(), format!("{:?}", arch.endianness));
        }

        Ok(FirmwareArtifact {
            id,
            source_name,
            hash,
            size: data.len() as u64,
            timestamp,
            container_type,
            nested_containers,
            filesystems,
            architecture,
            files,
            metadata,
            entropy,
            is_encrypted,
        })
    }

    /// Detect the primary container type
    fn detect_container_type(&self, data: &[u8]) -> ContainerType {
        container::detect_container_type(data)
    }

    /// Find all nested containers
    fn find_nested_containers(&self, data: &[u8], depth: usize) -> CoreResult<Vec<ContainerInfo>> {
        if depth >= self.max_recursion_depth {
            return Ok(Vec::new());
        }

        let mut containers = Vec::new();
        let scan_limit = std::cmp::min(data.len(), 64 * 1024);

        // Scan for container signatures
        let detections = magic::detect_all_formats(data, scan_limit);

        for (offset, format, description) in detections {
            if offset == 0 {
                continue; // Skip primary container
            }

            let container_type = container::format_to_container_type(&format);
            let size = container::estimate_container_size(&data[offset..], &format);

            containers.push(ContainerInfo {
                offset: offset as u64,
                size,
                container_type,
                description: description.to_string(),
                nested: Vec::new(),
            });
        }

        Ok(containers)
    }

    /// Extract filesystems from containers
    fn extract_filesystems(
        &self,
        data: &[u8],
        containers: &[ContainerInfo],
    ) -> CoreResult<Vec<ExtractedFilesystem>> {
        let mut filesystems = Vec::new();

        // Check primary data for filesystem
        if let Some(fs) = filesystem::try_extract_filesystem(data, 0) {
            filesystems.push(fs);
        }

        // Check nested containers
        for container in containers {
            let offset = container.offset as usize;
            let end = std::cmp::min(offset + container.size as usize, data.len());
            if offset < end {
                if let Some(fs) = filesystem::try_extract_filesystem(&data[offset..end], offset as u64) {
                    filesystems.push(fs);
                }
            }
        }

        Ok(filesystems)
    }

    /// Extract all files from filesystems and archives
    fn extract_all_files(
        &self,
        data: &[u8],
        filesystems: &[ExtractedFilesystem],
        containers: &[ContainerInfo],
    ) -> CoreResult<Vec<ExtractedFile>> {
        let mut files = Vec::new();

        // Extract from filesystems
        for fs in filesystems {
            files.extend(fs.files.clone());
        }

        // Extract from archive containers
        for container in containers {
            if container.is_archive() {
                let offset = container.offset as usize;
                let end = std::cmp::min(offset + container.size as usize, data.len());
                if offset < end {
                    let archive_files = self.extract_from_archive(&data[offset..end])?;
                    files.extend(archive_files);
                }
            }
        }

        // Scan raw data for embedded executables
        let embedded = self.find_embedded_executables(data)?;
        files.extend(embedded);

        // Deduplicate by hash
        files.sort_by(|a, b| a.hash.cmp(&b.hash));
        files.dedup_by(|a, b| a.hash == b.hash);

        Ok(files)
    }

    /// Extract files from archive
    fn extract_from_archive(&self, data: &[u8]) -> CoreResult<Vec<ExtractedFile>> {
        let mut files = Vec::new();

        // Try tar
        if fw_parsers::archives::TarParser.can_parse(data) {
            if let Ok(content) = fw_parsers::archives::TarParser.parse(data) {
                for entry in content.entries {
                    if entry.entry_type == fw_parsers::EntryType::File {
                        let file_data = fw_parsers::archives::extract_tar_entry(data, &entry.path).ok();
                        files.push(ExtractedFile {
                            path: entry.path,
                            size: entry.size,
                            file_type: FileType::Unknown,
                            hash: file_data.as_ref().map(|d| hash_data(d)).unwrap_or_default(),
                            data: file_data,
                            offset: entry.offset,
                        });
                    }
                }
            }
        }

        // Try zip
        if fw_parsers::archives::ZipParser.can_parse(data) {
            if let Ok(content) = fw_parsers::archives::ZipParser.parse(data) {
                for entry in content.entries {
                    if entry.entry_type == fw_parsers::EntryType::File {
                        let file_data = fw_parsers::archives::extract_zip_entry(data, &entry.path).ok();
                        files.push(ExtractedFile {
                            path: entry.path,
                            size: entry.size,
                            file_type: FileType::Unknown,
                            hash: file_data.as_ref().map(|d| hash_data(d)).unwrap_or_default(),
                            data: file_data,
                            offset: entry.offset,
                        });
                    }
                }
            }
        }

        // Determine file types
        for file in &mut files {
            if let Some(ref data) = file.data {
                file.file_type = filesystem::detect_file_type(data, &file.path);
            }
        }

        Ok(files)
    }

    /// Find embedded executables in raw data
    fn find_embedded_executables(&self, data: &[u8]) -> CoreResult<Vec<ExtractedFile>> {
        let mut files = Vec::new();
        let elf_magic = &[0x7F, b'E', b'L', b'F'];
        let pe_magic = &[b'M', b'Z'];

        // Scan for ELF executables
        for i in 0..data.len().saturating_sub(4) {
            if &data[i..i + 4] == elf_magic {
                // Found ELF, try to determine size
                if let Ok(analysis) = fw_parsers::elf::ElfParser::new().analyze(&data[i..]) {
                    let size = estimate_elf_size(&data[i..]);
                    let end = std::cmp::min(i + size, data.len());
                    let elf_data = data[i..end].to_vec();

                    files.push(ExtractedFile {
                        path: format!("embedded_elf_0x{:x}", i),
                        size: elf_data.len() as u64,
                        file_type: FileType::Elf,
                        hash: hash_data(&elf_data),
                        data: Some(elf_data),
                        offset: i as u64,
                    });
                }
            }
        }

        // Limit embedded executables to first 10 to avoid noise
        files.truncate(10);

        Ok(files)
    }

    /// Detect architecture from executable files
    fn detect_architecture(&self, files: &[ExtractedFile]) -> Option<ArchitectureInfo> {
        for file in files {
            if let Some(ref data) = file.data {
                if let Some(arch) = self.arch_detector.detect(data) {
                    return Some(arch);
                }
            }
        }
        None
    }
}

fn hash_data(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn estimate_elf_size(data: &[u8]) -> usize {
    if data.len() < 64 {
        return data.len();
    }

    // Parse ELF header to get section/program header info
    let is_64bit = data[4] == 2;

    if is_64bit && data.len() >= 64 {
        let shoff = u64::from_le_bytes([
            data[40], data[41], data[42], data[43],
            data[44], data[45], data[46], data[47],
        ]) as usize;
        let shentsize = u16::from_le_bytes([data[58], data[59]]) as usize;
        let shnum = u16::from_le_bytes([data[60], data[61]]) as usize;

        let size = shoff + (shentsize * shnum);
        return std::cmp::min(size, data.len());
    } else if data.len() >= 52 {
        let shoff = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;
        let shentsize = u16::from_le_bytes([data[46], data[47]]) as usize;
        let shnum = u16::from_le_bytes([data[48], data[49]]) as usize;

        let size = shoff + (shentsize * shnum);
        return std::cmp::min(size, data.len());
    }

    data.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingester_creation() {
        let ingester = Ingester::new(10);
        assert_eq!(ingester.max_recursion_depth, 10);
    }

    #[test]
    fn test_hash_data() {
        let hash = hash_data(b"test");
        assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars
    }
}
