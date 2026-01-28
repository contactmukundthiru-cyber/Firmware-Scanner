//! Container format detection and extraction
//!
//! Handles nested container detection, vendor-specific formats,
//! and Android-specific containers.

use crate::{
    magic, ArchiveType, ContentEntry, ContentFormat, ContentMetadata, EntryType, FilesystemType,
    FormatParser, ParseError, ParseResult, ParsedContent,
};
use std::collections::HashMap;

/// Container analysis result with nested structure
#[derive(Debug, Clone)]
pub struct ContainerAnalysis {
    pub format: ContainerFormat,
    pub nested_containers: Vec<NestedContainer>,
    pub total_size: u64,
    pub is_encrypted: bool,
    pub entropy: f64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum ContainerFormat {
    Archive(ArchiveType),
    Filesystem(FilesystemType),
    AndroidOTA,
    AndroidSparse,
    AndroidBootImage,
    UBootImage,
    VendorSpecific(String),
    Raw,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct NestedContainer {
    pub offset: u64,
    pub size: u64,
    pub format: ContainerFormat,
    pub description: String,
    pub entropy: f64,
}

/// Unified container parser that handles all formats
pub struct ContainerParser {
    max_recursion_depth: usize,
    scan_depth: usize,
}

impl ContainerParser {
    pub fn new() -> Self {
        Self {
            max_recursion_depth: 10,
            scan_depth: 64 * 1024, // Scan first 64KB for nested containers
        }
    }

    pub fn with_config(max_recursion_depth: usize, scan_depth: usize) -> Self {
        Self {
            max_recursion_depth,
            scan_depth,
        }
    }

    /// Analyze container and detect nested structures
    pub fn analyze(&self, data: &[u8]) -> ParseResult<ContainerAnalysis> {
        let entropy = magic::calculate_entropy(data);
        let is_encrypted = entropy > 7.9;

        // Detect primary format
        let format = self.detect_format(data);

        // Scan for nested containers
        let nested_containers = self.find_nested_containers(data, 0)?;

        let mut metadata = HashMap::new();
        metadata.insert("entropy".to_string(), format!("{:.4}", entropy));
        metadata.insert("size".to_string(), data.len().to_string());

        Ok(ContainerAnalysis {
            format,
            nested_containers,
            total_size: data.len() as u64,
            is_encrypted,
            entropy,
            metadata,
        })
    }

    /// Detect the primary container format
    fn detect_format(&self, data: &[u8]) -> ContainerFormat {
        // Check Android boot image
        if self.is_android_boot_image(data) {
            return ContainerFormat::AndroidBootImage;
        }

        // Check Android sparse image
        if self.is_android_sparse(data) {
            return ContainerFormat::AndroidSparse;
        }

        // Check U-Boot image
        if self.is_uboot_image(data) {
            return ContainerFormat::UBootImage;
        }

        // Use magic detection
        if let Some((fmt, _)) = magic::detect_format(data) {
            match fmt {
                ContentFormat::Archive(at) => ContainerFormat::Archive(at),
                ContentFormat::Filesystem(fs) => ContainerFormat::Filesystem(fs),
                _ => ContainerFormat::Unknown,
            }
        } else {
            ContainerFormat::Unknown
        }
    }

    /// Find all nested containers within data
    fn find_nested_containers(&self, data: &[u8], depth: usize) -> ParseResult<Vec<NestedContainer>> {
        if depth >= self.max_recursion_depth {
            return Ok(Vec::new());
        }

        let mut containers = Vec::new();
        let scan_limit = std::cmp::min(data.len(), self.scan_depth);

        // Scan for known signatures
        let signatures = magic::detect_all_formats(data, scan_limit);

        for (offset, format, desc) in signatures {
            if offset == 0 {
                continue; // Skip the primary format
            }

            let remaining = &data[offset..];
            let size = estimate_container_size(remaining, &format);
            let entropy = magic::calculate_entropy(&remaining[..std::cmp::min(remaining.len(), 4096)]);

            let container_format = match format {
                ContentFormat::Archive(at) => ContainerFormat::Archive(at),
                ContentFormat::Filesystem(fs) => ContainerFormat::Filesystem(fs),
                _ => ContainerFormat::Unknown,
            };

            containers.push(NestedContainer {
                offset: offset as u64,
                size,
                format: container_format,
                description: desc.to_string(),
                entropy,
            });
        }

        // Also scan for specific patterns
        containers.extend(self.find_android_containers(data)?);
        containers.extend(self.find_uboot_containers(data)?);

        // Sort by offset
        containers.sort_by_key(|c| c.offset);

        // Remove duplicates (same offset)
        containers.dedup_by_key(|c| c.offset);

        Ok(containers)
    }

    /// Check if data is Android boot image
    fn is_android_boot_image(&self, data: &[u8]) -> bool {
        data.len() >= 8 && &data[0..8] == b"ANDROID!"
    }

    /// Check if data is Android sparse image
    fn is_android_sparse(&self, data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == &[0x3A, 0xFF, 0x26, 0xED]
    }

    /// Check if data is U-Boot image
    fn is_uboot_image(&self, data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == &[0x27, 0x05, 0x19, 0x56]
    }

    /// Find Android-specific containers
    fn find_android_containers(&self, data: &[u8]) -> ParseResult<Vec<NestedContainer>> {
        let mut containers = Vec::new();

        // Search for Android boot image magic
        for i in 0..data.len().saturating_sub(8) {
            if &data[i..i + 8] == b"ANDROID!" {
                let size = self.parse_android_boot_size(&data[i..]);
                containers.push(NestedContainer {
                    offset: i as u64,
                    size,
                    format: ContainerFormat::AndroidBootImage,
                    description: "Android boot image".to_string(),
                    entropy: magic::calculate_entropy(&data[i..std::cmp::min(i + 4096, data.len())]),
                });
            }
        }

        // Search for sparse image magic
        for i in 0..data.len().saturating_sub(4) {
            if &data[i..i + 4] == &[0x3A, 0xFF, 0x26, 0xED] {
                let size = self.parse_sparse_size(&data[i..]);
                containers.push(NestedContainer {
                    offset: i as u64,
                    size,
                    format: ContainerFormat::AndroidSparse,
                    description: "Android sparse image".to_string(),
                    entropy: magic::calculate_entropy(&data[i..std::cmp::min(i + 4096, data.len())]),
                });
            }
        }

        Ok(containers)
    }

    /// Find U-Boot containers
    fn find_uboot_containers(&self, data: &[u8]) -> ParseResult<Vec<NestedContainer>> {
        let mut containers = Vec::new();

        // U-Boot image magic
        for i in 0..data.len().saturating_sub(4) {
            if &data[i..i + 4] == &[0x27, 0x05, 0x19, 0x56] {
                let size = self.parse_uboot_size(&data[i..]);
                containers.push(NestedContainer {
                    offset: i as u64,
                    size,
                    format: ContainerFormat::UBootImage,
                    description: "U-Boot legacy image".to_string(),
                    entropy: magic::calculate_entropy(&data[i..std::cmp::min(i + 4096, data.len())]),
                });
            }
        }

        Ok(containers)
    }

    /// Parse Android boot image to get total size
    fn parse_android_boot_size(&self, data: &[u8]) -> u64 {
        if data.len() < 1632 {
            return 0;
        }

        // Android boot image header v0-v2
        let page_size = u32::from_le_bytes([data[36], data[37], data[38], data[39]]) as u64;
        let kernel_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as u64;
        let ramdisk_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as u64;
        let second_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as u64;

        if page_size == 0 {
            return 0;
        }

        let pages = |size: u64| -> u64 {
            (size + page_size - 1) / page_size
        };

        (1 + pages(kernel_size) + pages(ramdisk_size) + pages(second_size)) * page_size
    }

    /// Parse Android sparse image to get total size
    fn parse_sparse_size(&self, data: &[u8]) -> u64 {
        if data.len() < 28 {
            return 0;
        }

        let block_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as u64;
        let total_blocks = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as u64;

        block_size * total_blocks
    }

    /// Parse U-Boot image to get total size
    fn parse_uboot_size(&self, data: &[u8]) -> u64 {
        if data.len() < 64 {
            return 0;
        }

        // U-Boot header is 64 bytes, data size at offset 12
        let data_size = u32::from_be_bytes([data[12], data[13], data[14], data[15]]) as u64;

        64 + data_size
    }
}

impl Default for ContainerParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FormatParser for ContainerParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        // Can parse anything, returns Unknown if not recognized
        !data.is_empty()
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let analysis = self.analyze(data)?;

        let entries: Vec<ContentEntry> = analysis
            .nested_containers
            .iter()
            .map(|c| ContentEntry {
                path: format!("nested_{}_{}", c.offset, c.description.replace(' ', "_")),
                entry_type: EntryType::File,
                offset: c.offset,
                size: c.size,
                compressed_size: None,
                data: None,
            })
            .collect();

        let format = match analysis.format {
            ContainerFormat::Archive(at) => ContentFormat::Archive(at),
            ContainerFormat::Filesystem(fs) => ContentFormat::Filesystem(fs),
            _ => ContentFormat::Unknown,
        };

        Ok(ParsedContent {
            format,
            entries,
            metadata: ContentMetadata {
                total_size: analysis.total_size,
                entry_count: analysis.nested_containers.len(),
                compression: None,
                endianness: None,
                word_size: None,
                extra: analysis.metadata,
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "Container"
    }
}

/// Estimate container size based on format
fn estimate_container_size(data: &[u8], format: &ContentFormat) -> u64 {
    match format {
        ContentFormat::Archive(ArchiveType::Gzip) => {
            // Gzip stores uncompressed size in last 4 bytes, but we want compressed size
            // For now, just use the full remaining data
            data.len() as u64
        }
        ContentFormat::Filesystem(FilesystemType::SquashFS) => {
            // SquashFS has size at offset 40
            if data.len() >= 44 {
                let bytes_used = u64::from_le_bytes([
                    data[40], data[41], data[42], data[43],
                    data[44], data[45], data[46], data[47],
                ]);
                bytes_used
            } else {
                data.len() as u64
            }
        }
        ContentFormat::Filesystem(FilesystemType::Ext4) => {
            // Ext4 superblock at offset 0x400, block count and size info there
            if data.len() >= 0x500 {
                let block_count = u32::from_le_bytes([
                    data[0x404], data[0x405], data[0x406], data[0x407],
                ]) as u64;
                let log_block_size = u32::from_le_bytes([
                    data[0x418], data[0x419], data[0x41A], data[0x41B],
                ]);
                let block_size = 1024u64 << log_block_size;
                block_count * block_size
            } else {
                data.len() as u64
            }
        }
        _ => data.len() as u64,
    }
}

/// Android boot image parser
pub struct AndroidBootImageParser;

impl AndroidBootImageParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse Android boot image header
    pub fn parse_header(&self, data: &[u8]) -> ParseResult<AndroidBootHeader> {
        if data.len() < 1632 {
            return Err(ParseError::TruncatedData {
                expected: 1632,
                actual: data.len(),
            });
        }

        if &data[0..8] != b"ANDROID!" {
            return Err(ParseError::InvalidMagic {
                offset: 0,
                expected: "ANDROID!".to_string(),
                actual: hex::encode(&data[0..8]),
            });
        }

        let kernel_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let kernel_addr = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let ramdisk_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let ramdisk_addr = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let second_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let second_addr = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
        let tags_addr = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let page_size = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

        // Extract command line (null-terminated string)
        let cmdline_bytes = &data[64..64 + 512];
        let cmdline_end = cmdline_bytes.iter().position(|&b| b == 0).unwrap_or(512);
        let cmdline = String::from_utf8_lossy(&cmdline_bytes[..cmdline_end]).to_string();

        // Extract board name
        let board_bytes = &data[576..576 + 16];
        let board_end = board_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let board_name = String::from_utf8_lossy(&board_bytes[..board_end]).to_string();

        Ok(AndroidBootHeader {
            kernel_size,
            kernel_addr,
            ramdisk_size,
            ramdisk_addr,
            second_size,
            second_addr,
            tags_addr,
            page_size,
            cmdline,
            board_name,
        })
    }

    /// Extract kernel from boot image
    pub fn extract_kernel<'a>(&self, data: &'a [u8]) -> ParseResult<&'a [u8]> {
        let header = self.parse_header(data)?;
        let page_size = header.page_size as usize;
        let kernel_offset = page_size; // Kernel starts after first page
        let kernel_end = kernel_offset + header.kernel_size as usize;

        if kernel_end > data.len() {
            return Err(ParseError::TruncatedData {
                expected: kernel_end,
                actual: data.len(),
            });
        }

        Ok(&data[kernel_offset..kernel_end])
    }

    /// Extract ramdisk from boot image
    pub fn extract_ramdisk<'a>(&self, data: &'a [u8]) -> ParseResult<&'a [u8]> {
        let header = self.parse_header(data)?;
        let page_size = header.page_size as usize;

        let kernel_pages = (header.kernel_size as usize + page_size - 1) / page_size;
        let ramdisk_offset = page_size + kernel_pages * page_size;
        let ramdisk_end = ramdisk_offset + header.ramdisk_size as usize;

        if ramdisk_end > data.len() {
            return Err(ParseError::TruncatedData {
                expected: ramdisk_end,
                actual: data.len(),
            });
        }

        Ok(&data[ramdisk_offset..ramdisk_end])
    }
}

#[derive(Debug, Clone)]
pub struct AndroidBootHeader {
    pub kernel_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_size: u32,
    pub ramdisk_addr: u32,
    pub second_size: u32,
    pub second_addr: u32,
    pub tags_addr: u32,
    pub page_size: u32,
    pub cmdline: String,
    pub board_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_parser_creation() {
        let parser = ContainerParser::new();
        assert_eq!(parser.max_recursion_depth, 10);
    }

    #[test]
    fn test_android_boot_detection() {
        let parser = ContainerParser::new();
        let mut data = vec![0u8; 2048];
        data[0..8].copy_from_slice(b"ANDROID!");
        assert!(parser.is_android_boot_image(&data));
    }

    #[test]
    fn test_uboot_detection() {
        let parser = ContainerParser::new();
        let data = [0x27, 0x05, 0x19, 0x56, 0x00, 0x00, 0x00, 0x00];
        assert!(parser.is_uboot_image(&data));
    }
}
