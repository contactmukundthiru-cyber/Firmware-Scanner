//! Magic byte detection for identifying file formats

use crate::{ArchiveType, ContentFormat, ExecutableType, FilesystemType};

/// Magic signature for format detection
#[derive(Debug, Clone)]
pub struct MagicSignature {
    pub offset: usize,
    pub bytes: &'static [u8],
    pub mask: Option<&'static [u8]>,
    pub format: ContentFormat,
    pub description: &'static str,
}

impl MagicSignature {
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.offset + self.bytes.len() {
            return false;
        }

        let slice = &data[self.offset..self.offset + self.bytes.len()];

        match self.mask {
            Some(mask) => {
                for i in 0..self.bytes.len() {
                    if (slice[i] & mask[i]) != (self.bytes[i] & mask[i]) {
                        return false;
                    }
                }
                true
            }
            None => slice == self.bytes,
        }
    }
}

/// All known magic signatures
pub static MAGIC_SIGNATURES: &[MagicSignature] = &[
    // ELF executables
    MagicSignature {
        offset: 0,
        bytes: &[0x7F, b'E', b'L', b'F', 1, 1], // 32-bit LE
        mask: None,
        format: ContentFormat::Executable(ExecutableType::Elf32Le),
        description: "ELF 32-bit LSB",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x7F, b'E', b'L', b'F', 1, 2], // 32-bit BE
        mask: None,
        format: ContentFormat::Executable(ExecutableType::Elf32Be),
        description: "ELF 32-bit MSB",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x7F, b'E', b'L', b'F', 2, 1], // 64-bit LE
        mask: None,
        format: ContentFormat::Executable(ExecutableType::Elf64Le),
        description: "ELF 64-bit LSB",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x7F, b'E', b'L', b'F', 2, 2], // 64-bit BE
        mask: None,
        format: ContentFormat::Executable(ExecutableType::Elf64Be),
        description: "ELF 64-bit MSB",
    },
    // PE executables
    MagicSignature {
        offset: 0,
        bytes: &[b'M', b'Z'],
        mask: None,
        format: ContentFormat::Executable(ExecutableType::Pe32),
        description: "DOS/PE executable",
    },
    // Archives
    MagicSignature {
        offset: 0,
        bytes: &[0x1f, 0x8b],
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Gzip),
        description: "gzip compressed",
    },
    MagicSignature {
        offset: 0,
        bytes: &[b'B', b'Z', b'h'],
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Bzip2),
        description: "bzip2 compressed",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0xFD, b'7', b'z', b'X', b'Z', 0x00],
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Xz),
        description: "xz compressed",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x04, 0x22, 0x4D, 0x18],
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Lz4),
        description: "lz4 compressed",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x28, 0xB5, 0x2F, 0xFD],
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Zstd),
        description: "zstd compressed",
    },
    MagicSignature {
        offset: 0,
        bytes: &[b'P', b'K', 0x03, 0x04],
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Zip),
        description: "ZIP archive",
    },
    MagicSignature {
        offset: 257,
        bytes: b"ustar",
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Tar),
        description: "POSIX tar archive",
    },
    // CPIO formats
    MagicSignature {
        offset: 0,
        bytes: &[0xC7, 0x71],
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Cpio),
        description: "cpio archive (old binary)",
    },
    MagicSignature {
        offset: 0,
        bytes: b"070701",
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Cpio),
        description: "cpio archive (newc)",
    },
    MagicSignature {
        offset: 0,
        bytes: b"070702",
        mask: None,
        format: ContentFormat::Archive(ArchiveType::Cpio),
        description: "cpio archive (newc with CRC)",
    },
    // Filesystems
    MagicSignature {
        offset: 0,
        bytes: b"hsqs",
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::SquashFS),
        description: "SquashFS (little-endian)",
    },
    MagicSignature {
        offset: 0,
        bytes: b"sqsh",
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::SquashFS),
        description: "SquashFS (big-endian)",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x28, 0xCD, 0x3D, 0x45],
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::CramFS),
        description: "CramFS (little-endian)",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x45, 0x3D, 0xCD, 0x28],
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::CramFS),
        description: "CramFS (big-endian)",
    },
    MagicSignature {
        offset: 0x438,
        bytes: &[0x53, 0xEF],
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::Ext4),
        description: "ext2/3/4 filesystem",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x85, 0x19],
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::JFFS2),
        description: "JFFS2 (little-endian)",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x19, 0x85],
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::JFFS2),
        description: "JFFS2 (big-endian)",
    },
    MagicSignature {
        offset: 0,
        bytes: b"UBI#",
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::UBI),
        description: "UBI image",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x31, 0x18, 0x10, 0x06],
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::UBIFS),
        description: "UBIFS superblock",
    },
    MagicSignature {
        offset: 0,
        bytes: &[0x2D, 0x72, 0x6F, 0x6D], // "-rom"
        mask: None,
        format: ContentFormat::Filesystem(FilesystemType::RomFS),
        description: "RomFS",
    },
];

/// Detect format from data
pub fn detect_format(data: &[u8]) -> Option<(ContentFormat, &'static str)> {
    // Check all signatures
    for sig in MAGIC_SIGNATURES {
        if sig.matches(data) {
            return Some((sig.format.clone(), sig.description));
        }
    }
    None
}

/// Detect all formats at various offsets (for nested containers)
pub fn detect_all_formats(data: &[u8], max_depth: usize) -> Vec<(usize, ContentFormat, &'static str)> {
    let mut results = Vec::new();

    // First check at offset 0
    if let Some((format, desc)) = detect_format(data) {
        results.push((0, format, desc));
    }

    // Scan for embedded signatures (limited depth for performance)
    let scan_limit = std::cmp::min(data.len(), max_depth);
    for offset in 1..scan_limit {
        if let Some((format, desc)) = detect_format(&data[offset..]) {
            results.push((offset, format, desc));
        }
    }

    results
}

/// Calculate entropy for a data block (for detecting encryption)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if data appears to be encrypted/compressed (high entropy)
pub fn is_high_entropy(data: &[u8]) -> bool {
    let entropy = calculate_entropy(data);
    // Encrypted/compressed data typically has entropy > 7.5
    entropy > 7.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_detection() {
        let elf32_le = [0x7F, b'E', b'L', b'F', 1, 1, 1, 0];
        let result = detect_format(&elf32_le);
        assert!(matches!(
            result,
            Some((ContentFormat::Executable(ExecutableType::Elf32Le), _))
        ));
    }

    #[test]
    fn test_gzip_detection() {
        let gzip = [0x1f, 0x8b, 0x08, 0x00];
        let result = detect_format(&gzip);
        assert!(matches!(
            result,
            Some((ContentFormat::Archive(ArchiveType::Gzip), _))
        ));
    }

    #[test]
    fn test_squashfs_detection() {
        let squashfs = b"hsqs\x00\x00\x00\x00";
        let result = detect_format(squashfs);
        assert!(matches!(
            result,
            Some((ContentFormat::Filesystem(FilesystemType::SquashFS), _))
        ));
    }

    #[test]
    fn test_entropy_calculation() {
        // Low entropy (repeated bytes)
        let low = vec![0u8; 1000];
        assert!(calculate_entropy(&low) < 1.0);

        // High entropy (random-ish)
        let high: Vec<u8> = (0..=255).cycle().take(1000).collect();
        assert!(calculate_entropy(&high) > 7.0);
    }
}
