//! Container type detection and handling

use fw_parsers::{ArchiveType, ContentFormat, FilesystemType};
use serde::{Deserialize, Serialize};

/// Container type enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerType {
    // Archives
    Tar,
    Zip,
    Gzip,
    Bzip2,
    Xz,
    Lz4,
    Zstd,
    Cpio,

    // Filesystems
    SquashFS,
    CramFS,
    Ext4,
    JFFS2,
    YAFFS,
    UBI,
    UBIFS,
    RomFS,

    // Platform specific
    AndroidOTA,
    AndroidSparse,
    AndroidBootImage,
    UBootImage,
    UBootFIT,

    // Vendor specific
    VendorCustom(String),

    // Encrypted/unknown
    Encrypted { scheme: Option<String> },
    Raw,
    Unknown,
}

impl ContainerType {
    pub fn is_archive(&self) -> bool {
        matches!(
            self,
            ContainerType::Tar
                | ContainerType::Zip
                | ContainerType::Gzip
                | ContainerType::Bzip2
                | ContainerType::Xz
                | ContainerType::Lz4
                | ContainerType::Zstd
                | ContainerType::Cpio
        )
    }

    pub fn is_filesystem(&self) -> bool {
        matches!(
            self,
            ContainerType::SquashFS
                | ContainerType::CramFS
                | ContainerType::Ext4
                | ContainerType::JFFS2
                | ContainerType::YAFFS
                | ContainerType::UBI
                | ContainerType::UBIFS
                | ContainerType::RomFS
        )
    }

    pub fn is_android(&self) -> bool {
        matches!(
            self,
            ContainerType::AndroidOTA
                | ContainerType::AndroidSparse
                | ContainerType::AndroidBootImage
        )
    }

    pub fn compression_name(&self) -> Option<&'static str> {
        match self {
            ContainerType::Gzip => Some("gzip"),
            ContainerType::Bzip2 => Some("bzip2"),
            ContainerType::Xz => Some("xz"),
            ContainerType::Lz4 => Some("lz4"),
            ContainerType::Zstd => Some("zstd"),
            _ => None,
        }
    }
}

/// Container information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub offset: u64,
    pub size: u64,
    pub container_type: ContainerType,
    pub description: String,
    pub nested: Vec<ContainerInfo>,
}

impl ContainerInfo {
    pub fn is_archive(&self) -> bool {
        self.container_type.is_archive()
    }

    pub fn is_filesystem(&self) -> bool {
        self.container_type.is_filesystem()
    }
}

/// Detect container type from data
pub fn detect_container_type(data: &[u8]) -> ContainerType {
    if data.len() < 4 {
        return ContainerType::Unknown;
    }

    // Check Android boot image
    if data.len() >= 8 && &data[0..8] == b"ANDROID!" {
        return ContainerType::AndroidBootImage;
    }

    // Check Android sparse
    if data.len() >= 4 && &data[0..4] == &[0x3A, 0xFF, 0x26, 0xED] {
        return ContainerType::AndroidSparse;
    }

    // Check U-Boot legacy
    if data.len() >= 4 && &data[0..4] == &[0x27, 0x05, 0x19, 0x56] {
        return ContainerType::UBootImage;
    }

    // Check U-Boot FIT (Device Tree Blob)
    if data.len() >= 4 && &data[0..4] == &[0xD0, 0x0D, 0xFE, 0xED] {
        return ContainerType::UBootFIT;
    }

    // Archives
    if data.len() >= 2 && &data[0..2] == &[0x1F, 0x8B] {
        return ContainerType::Gzip;
    }
    if data.len() >= 3 && &data[0..3] == b"BZh" {
        return ContainerType::Bzip2;
    }
    if data.len() >= 6 && &data[0..6] == &[0xFD, b'7', b'z', b'X', b'Z', 0x00] {
        return ContainerType::Xz;
    }
    if data.len() >= 4 && &data[0..4] == &[0x04, 0x22, 0x4D, 0x18] {
        return ContainerType::Lz4;
    }
    if data.len() >= 4 && &data[0..4] == &[0x28, 0xB5, 0x2F, 0xFD] {
        return ContainerType::Zstd;
    }
    if data.len() >= 4 && &data[0..4] == &[b'P', b'K', 0x03, 0x04] {
        return ContainerType::Zip;
    }
    if data.len() >= 263 && &data[257..262] == b"ustar" {
        return ContainerType::Tar;
    }
    if data.len() >= 6 && (&data[0..6] == b"070701" || &data[0..6] == b"070702") {
        return ContainerType::Cpio;
    }
    if data.len() >= 2 && &data[0..2] == &[0xC7, 0x71] {
        return ContainerType::Cpio;
    }

    // Filesystems
    if data.len() >= 4 && (&data[0..4] == b"hsqs" || &data[0..4] == b"sqsh") {
        return ContainerType::SquashFS;
    }
    if data.len() >= 4
        && (&data[0..4] == &[0x28, 0xCD, 0x3D, 0x45] || &data[0..4] == &[0x45, 0x3D, 0xCD, 0x28])
    {
        return ContainerType::CramFS;
    }
    if data.len() >= 0x43A && &data[0x438..0x43A] == &[0x53, 0xEF] {
        return ContainerType::Ext4;
    }
    if data.len() >= 2 && (&data[0..2] == &[0x85, 0x19] || &data[0..2] == &[0x19, 0x85]) {
        return ContainerType::JFFS2;
    }
    if data.len() >= 4 && &data[0..4] == b"UBI#" {
        return ContainerType::UBI;
    }
    if data.len() >= 4 && &data[0..4] == &[0x31, 0x18, 0x10, 0x06] {
        return ContainerType::UBIFS;
    }
    if data.len() >= 4 && &data[0..4] == b"-rom" {
        return ContainerType::RomFS;
    }

    // Check entropy for encryption
    let entropy = fw_parsers::magic::calculate_entropy(&data[..std::cmp::min(data.len(), 4096)]);
    if entropy > 7.9 {
        return ContainerType::Encrypted { scheme: None };
    }

    ContainerType::Unknown
}

/// Convert fw_parsers ContentFormat to ContainerType
pub fn format_to_container_type(format: &ContentFormat) -> ContainerType {
    match format {
        ContentFormat::Archive(at) => match at {
            ArchiveType::Tar => ContainerType::Tar,
            ArchiveType::Zip => ContainerType::Zip,
            ArchiveType::Gzip => ContainerType::Gzip,
            ArchiveType::Bzip2 => ContainerType::Bzip2,
            ArchiveType::Xz => ContainerType::Xz,
            ArchiveType::Lz4 => ContainerType::Lz4,
            ArchiveType::Zstd => ContainerType::Zstd,
            ArchiveType::Cpio => ContainerType::Cpio,
        },
        ContentFormat::Filesystem(fs) => match fs {
            FilesystemType::SquashFS => ContainerType::SquashFS,
            FilesystemType::CramFS => ContainerType::CramFS,
            FilesystemType::Ext4 | FilesystemType::Ext2 => ContainerType::Ext4,
            FilesystemType::JFFS2 => ContainerType::JFFS2,
            FilesystemType::YAFFS | FilesystemType::YAFFS2 => ContainerType::YAFFS,
            FilesystemType::UBI => ContainerType::UBI,
            FilesystemType::UBIFS => ContainerType::UBIFS,
            FilesystemType::RomFS => ContainerType::RomFS,
        },
        _ => ContainerType::Unknown,
    }
}

/// Estimate container size based on format
pub fn estimate_container_size(data: &[u8], format: &ContentFormat) -> u64 {
    match format {
        ContentFormat::Filesystem(FilesystemType::SquashFS) => {
            // SquashFS has bytes_used at offset 40
            if data.len() >= 48 {
                u64::from_le_bytes([
                    data[40], data[41], data[42], data[43],
                    data[44], data[45], data[46], data[47],
                ])
            } else {
                data.len() as u64
            }
        }
        ContentFormat::Filesystem(FilesystemType::Ext4 | FilesystemType::Ext2) => {
            // Ext4 superblock at 0x400
            if data.len() >= 0x500 {
                let sb = &data[0x400..];
                let block_count = u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]) as u64;
                let log_block_size = u32::from_le_bytes([sb[24], sb[25], sb[26], sb[27]]);
                let block_size = 1024u64 << log_block_size;
                block_count * block_size
            } else {
                data.len() as u64
            }
        }
        ContentFormat::Filesystem(FilesystemType::CramFS) => {
            // CramFS size at offset 4
            if data.len() >= 8 {
                u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64
            } else {
                data.len() as u64
            }
        }
        _ => data.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_detection_squashfs() {
        let data = b"hsqs\x00\x00\x00\x00";
        assert_eq!(detect_container_type(data), ContainerType::SquashFS);
    }

    #[test]
    fn test_container_detection_gzip() {
        let data = [0x1F, 0x8B, 0x08, 0x00];
        assert_eq!(detect_container_type(&data), ContainerType::Gzip);
    }

    #[test]
    fn test_container_detection_android_boot() {
        let data = b"ANDROID!padding";
        assert_eq!(detect_container_type(data), ContainerType::AndroidBootImage);
    }

    #[test]
    fn test_container_type_methods() {
        assert!(ContainerType::Tar.is_archive());
        assert!(ContainerType::SquashFS.is_filesystem());
        assert!(ContainerType::AndroidBootImage.is_android());
    }
}
