//! Filesystem extraction and file type detection

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// File type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    Elf,
    Pe,
    MachO,
    Script,
    Config,
    Text,
    Binary,
    Library,
    KernelModule,
    DeviceTree,
    Certificate,
    Key,
    Database,
    Archive,
    Image,
    Unknown,
}

impl FileType {
    pub fn is_executable(&self) -> bool {
        matches!(self, FileType::Elf | FileType::Pe | FileType::MachO | FileType::Script)
    }

    pub fn is_text(&self) -> bool {
        matches!(self, FileType::Script | FileType::Config | FileType::Text)
    }

    pub fn is_sensitive(&self) -> bool {
        matches!(self, FileType::Key | FileType::Certificate | FileType::Config | FileType::Database)
    }
}

/// Extracted file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    pub path: String,
    pub size: u64,
    pub file_type: FileType,
    pub hash: String,
    #[serde(skip)]
    pub data: Option<Vec<u8>>,
    pub offset: u64,
}

impl ExtractedFile {
    /// Check if file contains specific bytes
    pub fn contains_bytes(&self, needle: &[u8]) -> bool {
        if let Some(ref data) = self.data {
            data.windows(needle.len()).any(|w| w == needle)
        } else {
            false
        }
    }

    /// Extract strings from file
    pub fn extract_strings(&self, min_length: usize) -> Vec<String> {
        if let Some(ref data) = self.data {
            extract_strings(data, min_length)
        } else {
            Vec::new()
        }
    }
}

/// Extracted filesystem information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFilesystem {
    pub fs_type: String,
    pub offset: u64,
    pub size: u64,
    pub files: Vec<ExtractedFile>,
    pub metadata: HashMap<String, String>,
}

impl ExtractedFilesystem {
    /// Get all files of a specific type
    pub fn files_by_type(&self, file_type: FileType) -> Vec<&ExtractedFile> {
        self.files.iter().filter(|f| f.file_type == file_type).collect()
    }

    /// Find file by path
    pub fn find_file(&self, path: &str) -> Option<&ExtractedFile> {
        self.files.iter().find(|f| f.path == path || f.path.ends_with(path))
    }

    /// Get total file count
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

/// Try to extract filesystem from data
pub fn try_extract_filesystem(data: &[u8], base_offset: u64) -> Option<ExtractedFilesystem> {
    // Try SquashFS
    if data.len() >= 4 && (&data[0..4] == b"hsqs" || &data[0..4] == b"sqsh") {
        return extract_squashfs_info(data, base_offset);
    }

    // Try CramFS
    if data.len() >= 4
        && (&data[0..4] == &[0x28, 0xCD, 0x3D, 0x45] || &data[0..4] == &[0x45, 0x3D, 0xCD, 0x28])
    {
        return extract_cramfs_info(data, base_offset);
    }

    // Try ext4
    if data.len() >= 0x43A && &data[0x438..0x43A] == &[0x53, 0xEF] {
        return extract_ext4_info(data, base_offset);
    }

    // Try JFFS2
    if data.len() >= 2 && (&data[0..2] == &[0x85, 0x19] || &data[0..2] == &[0x19, 0x85]) {
        return extract_jffs2_info(data, base_offset);
    }

    None
}

fn extract_squashfs_info(data: &[u8], base_offset: u64) -> Option<ExtractedFilesystem> {
    if data.len() < 96 {
        return None;
    }

    let is_le = &data[0..4] == b"hsqs";
    let read_u32 = |offset: usize| -> u32 {
        if is_le {
            u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
        } else {
            u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
        }
    };

    let read_u64 = |offset: usize| -> u64 {
        if is_le {
            u64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ])
        } else {
            u64::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ])
        }
    };

    let inode_count = read_u32(4);
    let bytes_used = read_u64(40);
    let compression = read_u32(20) & 0xFFFF;

    let compression_name = match compression {
        1 => "gzip",
        2 => "lzma",
        3 => "lzo",
        4 => "xz",
        5 => "lz4",
        6 => "zstd",
        _ => "unknown",
    };

    let mut metadata = HashMap::new();
    metadata.insert("compression".to_string(), compression_name.to_string());
    metadata.insert("inode_count".to_string(), inode_count.to_string());

    Some(ExtractedFilesystem {
        fs_type: "SquashFS".to_string(),
        offset: base_offset,
        size: bytes_used,
        files: Vec::new(), // Full extraction requires decompression
        metadata,
    })
}

fn extract_cramfs_info(data: &[u8], base_offset: u64) -> Option<ExtractedFilesystem> {
    if data.len() < 76 {
        return None;
    }

    let is_le = &data[0..4] == &[0x28, 0xCD, 0x3D, 0x45];
    let read_u32 = |offset: usize| -> u32 {
        if is_le {
            u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
        } else {
            u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
        }
    };

    let size = read_u32(4);
    let files = read_u32(44);

    let name_bytes = &data[48..64];
    let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
    let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

    let mut metadata = HashMap::new();
    metadata.insert("name".to_string(), name);
    metadata.insert("file_count".to_string(), files.to_string());

    Some(ExtractedFilesystem {
        fs_type: "CramFS".to_string(),
        offset: base_offset,
        size: size as u64,
        files: Vec::new(),
        metadata,
    })
}

fn extract_ext4_info(data: &[u8], base_offset: u64) -> Option<ExtractedFilesystem> {
    if data.len() < 0x500 {
        return None;
    }

    let sb = &data[0x400..];

    let inode_count = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
    let block_count = u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]) as u64;
    let log_block_size = u32::from_le_bytes([sb[24], sb[25], sb[26], sb[27]]);
    let block_size = 1024u64 << log_block_size;

    let volume_name_bytes = &sb[0x78..0x88];
    let volume_name_end = volume_name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
    let volume_name = String::from_utf8_lossy(&volume_name_bytes[..volume_name_end]).to_string();

    let mut metadata = HashMap::new();
    metadata.insert("volume_name".to_string(), volume_name);
    metadata.insert("inode_count".to_string(), inode_count.to_string());
    metadata.insert("block_size".to_string(), block_size.to_string());

    Some(ExtractedFilesystem {
        fs_type: "ext4".to_string(),
        offset: base_offset,
        size: block_count * block_size,
        files: Vec::new(),
        metadata,
    })
}

fn extract_jffs2_info(data: &[u8], base_offset: u64) -> Option<ExtractedFilesystem> {
    // JFFS2 doesn't have a superblock, estimate size from data
    let mut metadata = HashMap::new();
    let endianness = if data[0] == 0x85 { "little" } else { "big" };
    metadata.insert("endianness".to_string(), endianness.to_string());

    Some(ExtractedFilesystem {
        fs_type: "JFFS2".to_string(),
        offset: base_offset,
        size: data.len() as u64,
        files: Vec::new(),
        metadata,
    })
}

/// Detect file type from content and path
pub fn detect_file_type(data: &[u8], path: &str) -> FileType {
    // Check magic bytes first
    if data.len() >= 4 && &data[0..4] == &[0x7F, b'E', b'L', b'F'] {
        // Check if it's a shared library or kernel module
        if path.ends_with(".so") || path.contains(".so.") {
            return FileType::Library;
        }
        if path.ends_with(".ko") {
            return FileType::KernelModule;
        }
        return FileType::Elf;
    }

    if data.len() >= 2 && &data[0..2] == &[b'M', b'Z'] {
        if path.ends_with(".dll") {
            return FileType::Library;
        }
        return FileType::Pe;
    }

    // Mach-O
    if data.len() >= 4 {
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCAFEBABE {
            return FileType::MachO;
        }
    }

    // Device tree
    if data.len() >= 4 && &data[0..4] == &[0xD0, 0x0D, 0xFE, 0xED] {
        return FileType::DeviceTree;
    }

    // Certificate
    if data.starts_with(b"-----BEGIN CERTIFICATE-----") {
        return FileType::Certificate;
    }

    // Key files
    if data.starts_with(b"-----BEGIN") && (data.windows(7).any(|w| w == b"PRIVATE") || data.windows(3).any(|w| w == b"KEY")) {
        return FileType::Key;
    }

    // SQLite
    if data.len() >= 16 && &data[0..16] == b"SQLite format 3\0" {
        return FileType::Database;
    }

    // Script detection by shebang
    if data.starts_with(b"#!") {
        return FileType::Script;
    }

    // Path-based detection
    let path_lower = path.to_lowercase();

    // Configuration files
    if path_lower.ends_with(".conf")
        || path_lower.ends_with(".cfg")
        || path_lower.ends_with(".ini")
        || path_lower.ends_with(".json")
        || path_lower.ends_with(".yaml")
        || path_lower.ends_with(".yml")
        || path_lower.ends_with(".xml")
        || path_lower.ends_with(".toml")
        || path_lower.contains("/etc/")
    {
        return FileType::Config;
    }

    // Script extensions
    if path_lower.ends_with(".sh")
        || path_lower.ends_with(".bash")
        || path_lower.ends_with(".py")
        || path_lower.ends_with(".pl")
        || path_lower.ends_with(".rb")
        || path_lower.ends_with(".lua")
    {
        return FileType::Script;
    }

    // Archives
    if path_lower.ends_with(".tar")
        || path_lower.ends_with(".gz")
        || path_lower.ends_with(".bz2")
        || path_lower.ends_with(".xz")
        || path_lower.ends_with(".zip")
    {
        return FileType::Archive;
    }

    // Images
    if path_lower.ends_with(".png")
        || path_lower.ends_with(".jpg")
        || path_lower.ends_with(".jpeg")
        || path_lower.ends_with(".gif")
        || path_lower.ends_with(".bmp")
        || path_lower.ends_with(".ico")
    {
        return FileType::Image;
    }

    // Text detection by content
    if is_text_content(data) {
        return FileType::Text;
    }

    FileType::Unknown
}

/// Check if content is text (printable ASCII)
fn is_text_content(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    let sample_size = std::cmp::min(data.len(), 1024);
    let sample = &data[..sample_size];

    let printable_count = sample
        .iter()
        .filter(|&&b| (b >= 0x20 && b < 0x7F) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();

    // Consider text if > 90% printable
    printable_count * 100 / sample_size > 90
}

/// Extract printable strings from data
pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte >= 0x20 && byte < 0x7F {
            current.push(byte);
        } else if byte == 0 && current.len() >= min_length {
            if let Ok(s) = String::from_utf8(current.clone()) {
                strings.push(s);
            }
            current.clear();
        } else {
            current.clear();
        }
    }

    // Check trailing string
    if current.len() >= min_length {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(s);
        }
    }

    strings
}

/// Hash file data
pub fn hash_file(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_detection_elf() {
        let data = [0x7F, b'E', b'L', b'F', 0x02, 0x01];
        assert_eq!(detect_file_type(&data, "/bin/ls"), FileType::Elf);
    }

    #[test]
    fn test_file_type_detection_library() {
        let data = [0x7F, b'E', b'L', b'F', 0x02, 0x01];
        assert_eq!(detect_file_type(&data, "/lib/libc.so.6"), FileType::Library);
    }

    #[test]
    fn test_file_type_detection_config() {
        let data = b"key=value\n";
        assert_eq!(detect_file_type(data, "/etc/config.conf"), FileType::Config);
    }

    #[test]
    fn test_file_type_detection_script() {
        let data = b"#!/bin/bash\necho hello";
        assert_eq!(detect_file_type(data, "script.sh"), FileType::Script);
    }

    #[test]
    fn test_string_extraction() {
        let data = b"Hello\0World\0ab\0LongString\0";
        let strings = extract_strings(data, 4);
        assert!(strings.contains(&"Hello".to_string()));
        assert!(strings.contains(&"World".to_string()));
        assert!(strings.contains(&"LongString".to_string()));
        assert!(!strings.iter().any(|s| s == "ab"));
    }

    #[test]
    fn test_text_detection() {
        assert!(is_text_content(b"This is plain text content."));
        assert!(!is_text_content(&[0x00, 0x01, 0x02, 0xFF, 0xFE]));
    }
}
