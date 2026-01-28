//! Filesystem parsers for embedded firmware formats
//!
//! Supports SquashFS, CramFS, JFFS2, YAFFS, UBI/UBIFS, ext4, RomFS

use crate::{
    ContentEntry, ContentFormat, ContentMetadata, Endianness, EntryType, FilesystemType,
    FormatParser, ParseError, ParseResult, ParsedContent,
};
use std::collections::HashMap;

/// SquashFS parser
pub struct SquashFSParser;

#[derive(Debug, Clone)]
pub struct SquashFSInfo {
    pub version_major: u16,
    pub version_minor: u16,
    pub compression: SquashFSCompression,
    pub block_size: u32,
    pub inode_count: u32,
    pub bytes_used: u64,
    pub root_inode: u64,
    pub endianness: Endianness,
    pub entries: Vec<SquashFSEntry>,
}

#[derive(Debug, Clone)]
pub struct SquashFSEntry {
    pub path: String,
    pub inode_type: u16,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SquashFSCompression {
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Lz4,
    Zstd,
    Unknown(u16),
}

impl SquashFSParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse SquashFS superblock
    pub fn parse_superblock(&self, data: &[u8]) -> ParseResult<SquashFSInfo> {
        if data.len() < 96 {
            return Err(ParseError::TruncatedData {
                expected: 96,
                actual: data.len(),
            });
        }

        // Detect endianness from magic
        let (endianness, magic_offset) = if &data[0..4] == b"hsqs" {
            (Endianness::Little, 0)
        } else if &data[0..4] == b"sqsh" {
            (Endianness::Big, 0)
        } else {
            return Err(ParseError::InvalidMagic {
                offset: 0,
                expected: "hsqs or sqsh".to_string(),
                actual: hex::encode(&data[0..4]),
            });
        };

        let read_u16 = |offset: usize| -> u16 {
            if endianness == Endianness::Little {
                u16::from_le_bytes([data[offset], data[offset + 1]])
            } else {
                u16::from_be_bytes([data[offset], data[offset + 1]])
            }
        };

        let read_u32 = |offset: usize| -> u32 {
            if endianness == Endianness::Little {
                u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            } else {
                u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            }
        };

        let read_u64 = |offset: usize| -> u64 {
            if endianness == Endianness::Little {
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
        let _mod_time = read_u32(8);
        let block_size = read_u32(12);
        let _frag_count = read_u32(16);
        let compression_id = read_u16(20);
        let _block_log = read_u16(22);
        let _flags = read_u16(24);
        let _id_count = read_u16(26);
        let version_major = read_u16(28);
        let version_minor = read_u16(30);
        let root_inode = read_u64(32);
        let bytes_used = read_u64(40);

        let compression = match compression_id {
            1 => SquashFSCompression::Gzip,
            2 => SquashFSCompression::Lzma,
            3 => SquashFSCompression::Lzo,
            4 => SquashFSCompression::Xz,
            5 => SquashFSCompression::Lz4,
            6 => SquashFSCompression::Zstd,
            other => SquashFSCompression::Unknown(other),
        };

        Ok(SquashFSInfo {
            version_major,
            version_minor,
            compression,
            block_size,
            inode_count,
            bytes_used,
            root_inode,
            endianness,
            entries: Vec::new(), // Full directory parsing requires decompression
        })
    }

    /// Get filesystem size
    pub fn get_size(&self, data: &[u8]) -> ParseResult<u64> {
        let info = self.parse_superblock(data)?;
        Ok(info.bytes_used)
    }
}

impl FormatParser for SquashFSParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 4 && (&data[0..4] == b"hsqs" || &data[0..4] == b"sqsh")
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let info = self.parse_superblock(data)?;

        let mut extra = HashMap::new();
        extra.insert("version".to_string(), format!("{}.{}", info.version_major, info.version_minor));
        extra.insert("compression".to_string(), format!("{:?}", info.compression));
        extra.insert("block_size".to_string(), info.block_size.to_string());
        extra.insert("inode_count".to_string(), info.inode_count.to_string());
        extra.insert("bytes_used".to_string(), info.bytes_used.to_string());

        Ok(ParsedContent {
            format: ContentFormat::Filesystem(FilesystemType::SquashFS),
            entries: Vec::new(),
            metadata: ContentMetadata {
                total_size: info.bytes_used,
                entry_count: info.inode_count as usize,
                compression: Some(format!("{:?}", info.compression)),
                endianness: Some(info.endianness),
                word_size: None,
                extra,
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "SquashFS"
    }
}

/// CramFS parser
pub struct CramFSParser;

#[derive(Debug, Clone)]
pub struct CramFSInfo {
    pub size: u32,
    pub flags: u32,
    pub future: u32,
    pub signature: [u8; 16],
    pub fsid: CramFSFsid,
    pub name: String,
    pub root_offset: u32,
    pub endianness: Endianness,
}

#[derive(Debug, Clone)]
pub struct CramFSFsid {
    pub crc: u32,
    pub edition: u32,
    pub blocks: u32,
    pub files: u32,
}

impl CramFSParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse CramFS superblock
    pub fn parse_superblock(&self, data: &[u8]) -> ParseResult<CramFSInfo> {
        if data.len() < 76 {
            return Err(ParseError::TruncatedData {
                expected: 76,
                actual: data.len(),
            });
        }

        // Detect endianness from magic
        let endianness = if &data[0..4] == &[0x28, 0xCD, 0x3D, 0x45] {
            Endianness::Little
        } else if &data[0..4] == &[0x45, 0x3D, 0xCD, 0x28] {
            Endianness::Big
        } else {
            return Err(ParseError::InvalidMagic {
                offset: 0,
                expected: "0x453DCD28".to_string(),
                actual: hex::encode(&data[0..4]),
            });
        };

        let read_u32 = |offset: usize| -> u32 {
            if endianness == Endianness::Little {
                u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            } else {
                u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            }
        };

        let size = read_u32(4);
        let flags = read_u32(8);
        let future = read_u32(12);

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&data[16..32]);

        let crc = read_u32(32);
        let edition = read_u32(36);
        let blocks = read_u32(40);
        let files = read_u32(44);

        let name_bytes = &data[48..64];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        let root_offset = read_u32(64);

        Ok(CramFSInfo {
            size,
            flags,
            future,
            signature,
            fsid: CramFSFsid { crc, edition, blocks, files },
            name,
            root_offset,
            endianness,
        })
    }
}

impl FormatParser for CramFSParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 4 &&
            (&data[0..4] == &[0x28, 0xCD, 0x3D, 0x45] || &data[0..4] == &[0x45, 0x3D, 0xCD, 0x28])
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let info = self.parse_superblock(data)?;

        let mut extra = HashMap::new();
        extra.insert("name".to_string(), info.name.clone());
        extra.insert("size".to_string(), info.size.to_string());
        extra.insert("blocks".to_string(), info.fsid.blocks.to_string());
        extra.insert("files".to_string(), info.fsid.files.to_string());
        extra.insert("edition".to_string(), info.fsid.edition.to_string());

        Ok(ParsedContent {
            format: ContentFormat::Filesystem(FilesystemType::CramFS),
            entries: Vec::new(),
            metadata: ContentMetadata {
                total_size: info.size as u64,
                entry_count: info.fsid.files as usize,
                compression: Some("zlib".to_string()),
                endianness: Some(info.endianness),
                word_size: None,
                extra,
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "CramFS"
    }
}

/// JFFS2 parser
pub struct JFFS2Parser;

#[derive(Debug, Clone)]
pub struct JFFS2Info {
    pub endianness: Endianness,
    pub nodes: Vec<JFFS2Node>,
    pub total_size: u64,
}

#[derive(Debug, Clone)]
pub struct JFFS2Node {
    pub magic: u16,
    pub node_type: u16,
    pub length: u32,
    pub offset: u64,
}

impl JFFS2Parser {
    pub fn new() -> Self {
        Self
    }

    /// Scan for JFFS2 nodes
    pub fn scan_nodes(&self, data: &[u8]) -> ParseResult<JFFS2Info> {
        // Detect endianness from magic
        let endianness = if data.len() >= 2 && data[0] == 0x85 && data[1] == 0x19 {
            Endianness::Little
        } else if data.len() >= 2 && data[0] == 0x19 && data[1] == 0x85 {
            Endianness::Big
        } else {
            return Err(ParseError::InvalidMagic {
                offset: 0,
                expected: "0x1985".to_string(),
                actual: hex::encode(&data[0..std::cmp::min(2, data.len())]),
            });
        };

        let magic_le: u16 = 0x1985;
        let magic_be: u16 = 0x8519;
        let expected_magic = if endianness == Endianness::Little { magic_le } else { magic_be };

        let mut nodes = Vec::new();
        let mut offset = 0;

        while offset + 12 <= data.len() {
            let magic = if endianness == Endianness::Little {
                u16::from_le_bytes([data[offset], data[offset + 1]])
            } else {
                u16::from_be_bytes([data[offset], data[offset + 1]])
            };

            if magic == expected_magic || magic == 0x1985 || magic == 0x8519 {
                let node_type = if endianness == Endianness::Little {
                    u16::from_le_bytes([data[offset + 2], data[offset + 3]])
                } else {
                    u16::from_be_bytes([data[offset + 2], data[offset + 3]])
                };

                let length = if endianness == Endianness::Little {
                    u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]])
                } else {
                    u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]])
                };

                nodes.push(JFFS2Node {
                    magic,
                    node_type,
                    length,
                    offset: offset as u64,
                });

                // Move to next node (aligned to 4 bytes)
                let next_offset = offset + length as usize;
                offset = (next_offset + 3) & !3;
            } else {
                // Skip erased area (0xFF) or scan forward
                offset += 4;
            }
        }

        Ok(JFFS2Info {
            endianness,
            nodes,
            total_size: data.len() as u64,
        })
    }
}

impl FormatParser for JFFS2Parser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 2 &&
            ((data[0] == 0x85 && data[1] == 0x19) || (data[0] == 0x19 && data[1] == 0x85))
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let info = self.scan_nodes(data)?;

        let entries: Vec<ContentEntry> = info.nodes.iter().map(|n| {
            ContentEntry {
                path: format!("node_0x{:x}", n.offset),
                entry_type: EntryType::File,
                offset: n.offset,
                size: n.length as u64,
                compressed_size: None,
                data: None,
            }
        }).collect();

        let mut extra = HashMap::new();
        extra.insert("node_count".to_string(), info.nodes.len().to_string());

        Ok(ParsedContent {
            format: ContentFormat::Filesystem(FilesystemType::JFFS2),
            entries,
            metadata: ContentMetadata {
                total_size: info.total_size,
                entry_count: info.nodes.len(),
                compression: Some("zlib/lzo".to_string()),
                endianness: Some(info.endianness),
                word_size: None,
                extra,
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "JFFS2"
    }
}

/// UBI parser
pub struct UBIParser;

#[derive(Debug, Clone)]
pub struct UBIInfo {
    pub version: u8,
    pub ec: u64,
    pub vid_hdr_offset: u32,
    pub data_offset: u32,
    pub volumes: Vec<UBIVolume>,
}

#[derive(Debug, Clone)]
pub struct UBIVolume {
    pub vol_id: u32,
    pub vol_type: u8,
    pub name: String,
    pub used_ebs: u32,
}

impl UBIParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse UBI EC header
    pub fn parse_ec_header(&self, data: &[u8]) -> ParseResult<UBIInfo> {
        if data.len() < 64 {
            return Err(ParseError::TruncatedData {
                expected: 64,
                actual: data.len(),
            });
        }

        // UBI magic "UBI#"
        if &data[0..4] != b"UBI#" {
            return Err(ParseError::InvalidMagic {
                offset: 0,
                expected: "UBI#".to_string(),
                actual: String::from_utf8_lossy(&data[0..4]).to_string(),
            });
        }

        let version = data[4];
        let ec = u64::from_be_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);
        let vid_hdr_offset = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let data_offset = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);

        Ok(UBIInfo {
            version,
            ec,
            vid_hdr_offset,
            data_offset,
            volumes: Vec::new(), // Volume scanning requires full image traversal
        })
    }
}

impl FormatParser for UBIParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == b"UBI#"
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let info = self.parse_ec_header(data)?;

        let mut extra = HashMap::new();
        extra.insert("version".to_string(), info.version.to_string());
        extra.insert("erase_counter".to_string(), info.ec.to_string());
        extra.insert("vid_hdr_offset".to_string(), info.vid_hdr_offset.to_string());
        extra.insert("data_offset".to_string(), info.data_offset.to_string());

        Ok(ParsedContent {
            format: ContentFormat::Filesystem(FilesystemType::UBI),
            entries: Vec::new(),
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: 0,
                compression: None,
                endianness: Some(Endianness::Big),
                word_size: None,
                extra,
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "UBI"
    }
}

/// Ext4 parser (basic superblock parsing)
pub struct Ext4Parser;

#[derive(Debug, Clone)]
pub struct Ext4Info {
    pub block_count: u64,
    pub block_size: u32,
    pub inode_count: u32,
    pub free_blocks: u64,
    pub free_inodes: u32,
    pub volume_name: String,
    pub uuid: [u8; 16],
    pub last_mounted: String,
    pub features_compat: u32,
    pub features_incompat: u32,
    pub features_ro_compat: u32,
}

impl Ext4Parser {
    pub fn new() -> Self {
        Self
    }

    /// Parse ext4 superblock (at offset 0x400)
    pub fn parse_superblock(&self, data: &[u8]) -> ParseResult<Ext4Info> {
        if data.len() < 0x400 + 256 {
            return Err(ParseError::TruncatedData {
                expected: 0x400 + 256,
                actual: data.len(),
            });
        }

        let sb = &data[0x400..];

        // Check magic
        if &sb[0x38..0x3A] != &[0x53, 0xEF] {
            return Err(ParseError::InvalidMagic {
                offset: 0x438,
                expected: "0xEF53".to_string(),
                actual: hex::encode(&sb[0x38..0x3A]),
            });
        }

        let inode_count = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
        let block_count_lo = u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]) as u64;
        let free_blocks_lo = u32::from_le_bytes([sb[12], sb[13], sb[14], sb[15]]) as u64;
        let free_inodes = u32::from_le_bytes([sb[16], sb[17], sb[18], sb[19]]);
        let log_block_size = u32::from_le_bytes([sb[24], sb[25], sb[26], sb[27]]);
        let block_size = 1024u32 << log_block_size;

        let features_compat = u32::from_le_bytes([sb[0x5C], sb[0x5D], sb[0x5E], sb[0x5F]]);
        let features_incompat = u32::from_le_bytes([sb[0x60], sb[0x61], sb[0x62], sb[0x63]]);
        let features_ro_compat = u32::from_le_bytes([sb[0x64], sb[0x65], sb[0x66], sb[0x67]]);

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&sb[0x68..0x78]);

        let volume_name_bytes = &sb[0x78..0x88];
        let volume_name_end = volume_name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let volume_name = String::from_utf8_lossy(&volume_name_bytes[..volume_name_end]).to_string();

        let last_mounted_bytes = &sb[0x88..0xC8];
        let last_mounted_end = last_mounted_bytes.iter().position(|&b| b == 0).unwrap_or(64);
        let last_mounted = String::from_utf8_lossy(&last_mounted_bytes[..last_mounted_end]).to_string();

        // 64-bit block count (if feature enabled)
        let block_count_hi = if features_incompat & 0x80 != 0 {
            u32::from_le_bytes([sb[0x150], sb[0x151], sb[0x152], sb[0x153]]) as u64
        } else {
            0
        };
        let block_count = block_count_lo | (block_count_hi << 32);

        let free_blocks_hi = if features_incompat & 0x80 != 0 {
            u32::from_le_bytes([sb[0x158], sb[0x159], sb[0x15A], sb[0x15B]]) as u64
        } else {
            0
        };
        let free_blocks = free_blocks_lo | (free_blocks_hi << 32);

        Ok(Ext4Info {
            block_count,
            block_size,
            inode_count,
            free_blocks,
            free_inodes,
            volume_name,
            uuid,
            last_mounted,
            features_compat,
            features_incompat,
            features_ro_compat,
        })
    }
}

impl FormatParser for Ext4Parser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 0x43A && data[0x438] == 0x53 && data[0x439] == 0xEF
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let info = self.parse_superblock(data)?;

        let mut extra = HashMap::new();
        extra.insert("volume_name".to_string(), info.volume_name.clone());
        extra.insert("block_size".to_string(), info.block_size.to_string());
        extra.insert("block_count".to_string(), info.block_count.to_string());
        extra.insert("inode_count".to_string(), info.inode_count.to_string());
        extra.insert("free_blocks".to_string(), info.free_blocks.to_string());
        extra.insert("free_inodes".to_string(), info.free_inodes.to_string());
        extra.insert("uuid".to_string(), hex::encode(info.uuid));
        extra.insert("last_mounted".to_string(), info.last_mounted.clone());

        let total_size = info.block_count * info.block_size as u64;

        Ok(ParsedContent {
            format: ContentFormat::Filesystem(FilesystemType::Ext4),
            entries: Vec::new(),
            metadata: ContentMetadata {
                total_size,
                entry_count: info.inode_count as usize,
                compression: None,
                endianness: Some(Endianness::Little),
                word_size: None,
                extra,
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "ext4"
    }
}

/// Get all filesystem parsers
pub fn all_parsers() -> Vec<Box<dyn FormatParser>> {
    vec![
        Box::new(SquashFSParser::new()),
        Box::new(CramFSParser::new()),
        Box::new(JFFS2Parser::new()),
        Box::new(UBIParser::new()),
        Box::new(Ext4Parser::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_squashfs_detection() {
        let parser = SquashFSParser::new();
        let le_magic = b"hsqs\x00\x00\x00\x00";
        let be_magic = b"sqsh\x00\x00\x00\x00";
        assert!(parser.can_parse(le_magic));
        assert!(parser.can_parse(be_magic));
    }

    #[test]
    fn test_cramfs_detection() {
        let parser = CramFSParser::new();
        let le_magic = [0x28, 0xCD, 0x3D, 0x45];
        let be_magic = [0x45, 0x3D, 0xCD, 0x28];
        assert!(parser.can_parse(&le_magic));
        assert!(parser.can_parse(&be_magic));
    }

    #[test]
    fn test_ubi_detection() {
        let parser = UBIParser::new();
        let magic = b"UBI#";
        assert!(parser.can_parse(magic));
    }
}
