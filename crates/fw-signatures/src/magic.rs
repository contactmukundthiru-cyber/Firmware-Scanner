//! Magic byte signatures for file format detection

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Magic signature for file type detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicSignature {
    pub name: String,
    pub description: String,
    pub offset: usize,
    pub bytes: Vec<u8>,
    pub mask: Option<Vec<u8>>,
    pub file_extension: Option<String>,
    pub mime_type: Option<String>,
}

impl MagicSignature {
    /// Check if data matches this signature
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.offset + self.bytes.len() {
            return false;
        }

        let slice = &data[self.offset..self.offset + self.bytes.len()];

        match &self.mask {
            Some(mask) => {
                for i in 0..self.bytes.len() {
                    if (slice[i] & mask[i]) != (self.bytes[i] & mask[i]) {
                        return false;
                    }
                }
                true
            }
            None => slice == self.bytes.as_slice(),
        }
    }
}

/// Firmware-specific magic signatures
pub fn firmware_magic_signatures() -> Vec<MagicSignature> {
    vec![
        // Android
        MagicSignature {
            name: "Android Boot Image".to_string(),
            description: "Android boot.img".to_string(),
            offset: 0,
            bytes: b"ANDROID!".to_vec(),
            mask: None,
            file_extension: Some("img".to_string()),
            mime_type: Some("application/x-android-boot-image".to_string()),
        },
        MagicSignature {
            name: "Android Sparse Image".to_string(),
            description: "Android sparse ext4 image".to_string(),
            offset: 0,
            bytes: vec![0x3A, 0xFF, 0x26, 0xED],
            mask: None,
            file_extension: Some("img".to_string()),
            mime_type: Some("application/x-android-sparse-image".to_string()),
        },
        // U-Boot
        MagicSignature {
            name: "U-Boot Legacy Image".to_string(),
            description: "U-Boot mkimage legacy format".to_string(),
            offset: 0,
            bytes: vec![0x27, 0x05, 0x19, 0x56],
            mask: None,
            file_extension: Some("img".to_string()),
            mime_type: Some("application/x-uboot-legacy".to_string()),
        },
        MagicSignature {
            name: "U-Boot FIT Image".to_string(),
            description: "U-Boot Flattened Image Tree".to_string(),
            offset: 0,
            bytes: vec![0xD0, 0x0D, 0xFE, 0xED],
            mask: None,
            file_extension: Some("itb".to_string()),
            mime_type: Some("application/x-uboot-fit".to_string()),
        },
        // Firmware containers
        MagicSignature {
            name: "Cisco IOS".to_string(),
            description: "Cisco IOS firmware".to_string(),
            offset: 0,
            bytes: vec![0x4D, 0x5A, 0x49, 0x00],
            mask: None,
            file_extension: Some("bin".to_string()),
            mime_type: Some("application/x-cisco-ios".to_string()),
        },
        MagicSignature {
            name: "TP-Link Firmware".to_string(),
            description: "TP-Link router firmware".to_string(),
            offset: 0,
            bytes: vec![0x01, 0x00, 0x00, 0x00],
            mask: Some(vec![0xFF, 0xFF, 0xFF, 0x00]),
            file_extension: Some("bin".to_string()),
            mime_type: Some("application/x-tplink-firmware".to_string()),
        },
        // RTOS images
        MagicSignature {
            name: "FreeRTOS".to_string(),
            description: "FreeRTOS configuration header".to_string(),
            offset: 0,
            bytes: b"FreeRTOSConfig".to_vec(),
            mask: None,
            file_extension: None,
            mime_type: None,
        },
        MagicSignature {
            name: "VxWorks".to_string(),
            description: "VxWorks RTOS image".to_string(),
            offset: 0,
            bytes: b"VxWorks".to_vec(),
            mask: None,
            file_extension: None,
            mime_type: Some("application/x-vxworks".to_string()),
        },
        // Firmware update packages
        MagicSignature {
            name: "SWU Update".to_string(),
            description: "SWUpdate software update package".to_string(),
            offset: 0,
            bytes: b"sw-description".to_vec(),
            mask: None,
            file_extension: Some("swu".to_string()),
            mime_type: Some("application/x-swupdate".to_string()),
        },
        MagicSignature {
            name: "RAUC Bundle".to_string(),
            description: "RAUC update bundle".to_string(),
            offset: 0,
            bytes: b"manifest.raucm".to_vec(),
            mask: None,
            file_extension: Some("raucb".to_string()),
            mime_type: Some("application/x-rauc".to_string()),
        },
    ]
}

/// Detect file type from magic bytes
pub fn detect_file_type(data: &[u8]) -> Option<&'static str> {
    // ELF
    if data.len() >= 4 && &data[0..4] == &[0x7F, b'E', b'L', b'F'] {
        return Some("ELF executable");
    }

    // PE/COFF
    if data.len() >= 2 && &data[0..2] == &[b'M', b'Z'] {
        return Some("PE executable");
    }

    // Archives
    if data.len() >= 2 && &data[0..2] == &[0x1F, 0x8B] {
        return Some("gzip compressed");
    }
    if data.len() >= 3 && &data[0..3] == b"BZh" {
        return Some("bzip2 compressed");
    }
    if data.len() >= 6 && &data[0..6] == &[0xFD, b'7', b'z', b'X', b'Z', 0x00] {
        return Some("xz compressed");
    }
    if data.len() >= 4 && &data[0..4] == &[0x28, 0xB5, 0x2F, 0xFD] {
        return Some("zstd compressed");
    }
    if data.len() >= 4 && &data[0..4] == &[b'P', b'K', 0x03, 0x04] {
        return Some("ZIP archive");
    }
    if data.len() >= 263 && &data[257..262] == b"ustar" {
        return Some("tar archive");
    }

    // Filesystems
    if data.len() >= 4 && (&data[0..4] == b"hsqs" || &data[0..4] == b"sqsh") {
        return Some("SquashFS filesystem");
    }
    if data.len() >= 4 && (&data[0..4] == &[0x28, 0xCD, 0x3D, 0x45] || &data[0..4] == &[0x45, 0x3D, 0xCD, 0x28]) {
        return Some("CramFS filesystem");
    }
    if data.len() >= 0x43A && &data[0x438..0x43A] == &[0x53, 0xEF] {
        return Some("ext2/3/4 filesystem");
    }
    if data.len() >= 2 && (&data[0..2] == &[0x85, 0x19] || &data[0..2] == &[0x19, 0x85]) {
        return Some("JFFS2 filesystem");
    }
    if data.len() >= 4 && &data[0..4] == b"UBI#" {
        return Some("UBI image");
    }

    // Android
    if data.len() >= 8 && &data[0..8] == b"ANDROID!" {
        return Some("Android boot image");
    }
    if data.len() >= 4 && &data[0..4] == &[0x3A, 0xFF, 0x26, 0xED] {
        return Some("Android sparse image");
    }

    // U-Boot
    if data.len() >= 4 && &data[0..4] == &[0x27, 0x05, 0x19, 0x56] {
        return Some("U-Boot legacy image");
    }
    if data.len() >= 4 && &data[0..4] == &[0xD0, 0x0D, 0xFE, 0xED] {
        return Some("Device Tree Blob / U-Boot FIT");
    }

    None
}

/// Multi-format detector for nested containers
pub struct MagicDetector {
    signatures: Vec<MagicSignature>,
}

impl MagicDetector {
    pub fn new() -> Self {
        Self {
            signatures: firmware_magic_signatures(),
        }
    }

    pub fn with_signatures(signatures: Vec<MagicSignature>) -> Self {
        Self { signatures }
    }

    /// Detect format at offset 0
    pub fn detect(&self, data: &[u8]) -> Option<&MagicSignature> {
        for sig in &self.signatures {
            if sig.matches(data) {
                return Some(sig);
            }
        }
        None
    }

    /// Scan for all signatures at various offsets
    pub fn scan(&self, data: &[u8], max_offset: usize) -> Vec<(usize, &MagicSignature)> {
        let mut matches = Vec::new();
        let limit = std::cmp::min(data.len(), max_offset);

        for offset in 0..limit {
            for sig in &self.signatures {
                if sig.offset == 0 {
                    let shifted_sig = MagicSignature {
                        offset,
                        ..sig.clone()
                    };
                    if shifted_sig.matches(data) {
                        matches.push((offset, sig));
                    }
                }
            }
        }

        matches
    }
}

impl Default for MagicDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_detection() {
        assert_eq!(detect_file_type(&[0x7F, b'E', b'L', b'F']), Some("ELF executable"));
        assert_eq!(detect_file_type(b"MZ"), Some("PE executable"));
        assert_eq!(detect_file_type(b"hsqs"), Some("SquashFS filesystem"));
        assert_eq!(detect_file_type(b"ANDROID!"), Some("Android boot image"));
    }

    #[test]
    fn test_signature_matching() {
        let sig = MagicSignature {
            name: "Test".to_string(),
            description: "Test sig".to_string(),
            offset: 0,
            bytes: vec![0x7F, b'E', b'L', b'F'],
            mask: None,
            file_extension: None,
            mime_type: None,
        };

        assert!(sig.matches(&[0x7F, b'E', b'L', b'F', 0x01, 0x01]));
        assert!(!sig.matches(&[0x7F, b'E', b'L', b'G']));
    }
}
