//! Archive format parsers (tar, zip, gzip, bzip2, xz, lz4, zstd)

use crate::{
    ArchiveType, ContentEntry, ContentFormat, ContentMetadata, EntryType, FormatParser,
    ParseError, ParseResult, ParsedContent,
};
use flate2::read::GzDecoder;
use std::io::{Cursor, Read};

/// Gzip decompressor
pub struct GzipParser;

impl FormatParser for GzipParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let mut decoder = GzDecoder::new(Cursor::new(data));
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| ParseError::Decompression(format!("gzip: {}", e)))?;

        Ok(ParsedContent {
            format: ContentFormat::Archive(ArchiveType::Gzip),
            entries: vec![ContentEntry {
                path: "decompressed".to_string(),
                entry_type: EntryType::File,
                offset: 0,
                size: decompressed.len() as u64,
                compressed_size: Some(data.len() as u64),
                data: Some(decompressed),
            }],
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: 1,
                compression: Some("gzip".to_string()),
                ..Default::default()
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "gzip"
    }
}

/// Bzip2 decompressor
pub struct Bzip2Parser;

impl FormatParser for Bzip2Parser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 3 && &data[0..3] == b"BZh"
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let mut decoder = bzip2::read::BzDecoder::new(Cursor::new(data));
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| ParseError::Decompression(format!("bzip2: {}", e)))?;

        Ok(ParsedContent {
            format: ContentFormat::Archive(ArchiveType::Bzip2),
            entries: vec![ContentEntry {
                path: "decompressed".to_string(),
                entry_type: EntryType::File,
                offset: 0,
                size: decompressed.len() as u64,
                compressed_size: Some(data.len() as u64),
                data: Some(decompressed),
            }],
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: 1,
                compression: Some("bzip2".to_string()),
                ..Default::default()
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "bzip2"
    }
}

/// XZ decompressor
pub struct XzParser;

impl FormatParser for XzParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 6 && &data[0..6] == &[0xFD, b'7', b'z', b'X', b'Z', 0x00]
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let mut decoder = xz2::read::XzDecoder::new(Cursor::new(data));
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| ParseError::Decompression(format!("xz: {}", e)))?;

        Ok(ParsedContent {
            format: ContentFormat::Archive(ArchiveType::Xz),
            entries: vec![ContentEntry {
                path: "decompressed".to_string(),
                entry_type: EntryType::File,
                offset: 0,
                size: decompressed.len() as u64,
                compressed_size: Some(data.len() as u64),
                data: Some(decompressed),
            }],
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: 1,
                compression: Some("xz".to_string()),
                ..Default::default()
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "xz"
    }
}

/// LZ4 decompressor
pub struct Lz4Parser;

impl FormatParser for Lz4Parser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == &[0x04, 0x22, 0x4D, 0x18]
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let decompressed = lz4_flex::decompress_size_prepended(data)
            .map_err(|e| ParseError::Decompression(format!("lz4: {}", e)))?;

        Ok(ParsedContent {
            format: ContentFormat::Archive(ArchiveType::Lz4),
            entries: vec![ContentEntry {
                path: "decompressed".to_string(),
                entry_type: EntryType::File,
                offset: 0,
                size: decompressed.len() as u64,
                compressed_size: Some(data.len() as u64),
                data: Some(decompressed),
            }],
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: 1,
                compression: Some("lz4".to_string()),
                ..Default::default()
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "lz4"
    }
}

/// Zstd decompressor
pub struct ZstdParser;

impl FormatParser for ZstdParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == &[0x28, 0xB5, 0x2F, 0xFD]
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let decompressed = zstd::decode_all(Cursor::new(data))
            .map_err(|e| ParseError::Decompression(format!("zstd: {}", e)))?;

        Ok(ParsedContent {
            format: ContentFormat::Archive(ArchiveType::Zstd),
            entries: vec![ContentEntry {
                path: "decompressed".to_string(),
                entry_type: EntryType::File,
                offset: 0,
                size: decompressed.len() as u64,
                compressed_size: Some(data.len() as u64),
                data: Some(decompressed),
            }],
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: 1,
                compression: Some("zstd".to_string()),
                ..Default::default()
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "zstd"
    }
}

/// Tar archive parser
pub struct TarParser;

impl FormatParser for TarParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        // Check for ustar magic at offset 257
        data.len() >= 263 && &data[257..262] == b"ustar"
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let mut archive = tar::Archive::new(Cursor::new(data));
        let mut entries = Vec::new();

        for entry in archive.entries().map_err(|e| ParseError::Archive(e.to_string()))? {
            let entry = entry.map_err(|e| ParseError::Archive(e.to_string()))?;
            let path = entry
                .path()
                .map_err(|e| ParseError::Archive(e.to_string()))?
                .to_string_lossy()
                .to_string();

            let entry_type = match entry.header().entry_type() {
                tar::EntryType::Regular => EntryType::File,
                tar::EntryType::Directory => EntryType::Directory,
                tar::EntryType::Symlink | tar::EntryType::Link => EntryType::Symlink,
                tar::EntryType::Char | tar::EntryType::Block => EntryType::Device,
                _ => EntryType::Unknown,
            };

            entries.push(ContentEntry {
                path,
                entry_type,
                offset: entry.raw_file_position(),
                size: entry.size(),
                compressed_size: None,
                data: None, // Don't load all data into memory
            });
        }

        Ok(ParsedContent {
            format: ContentFormat::Archive(ArchiveType::Tar),
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: entries.len(),
                ..Default::default()
            },
            entries,
        })
    }

    fn format_name(&self) -> &'static str {
        "tar"
    }
}

/// ZIP archive parser
pub struct ZipParser;

impl FormatParser for ZipParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == &[b'P', b'K', 0x03, 0x04]
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let reader = Cursor::new(data);
        let mut archive =
            zip::ZipArchive::new(reader).map_err(|e| ParseError::Archive(e.to_string()))?;

        let mut entries = Vec::new();

        for i in 0..archive.len() {
            let file = archive
                .by_index_raw(i)
                .map_err(|e| ParseError::Archive(e.to_string()))?;

            let entry_type = if file.is_dir() {
                EntryType::Directory
            } else {
                EntryType::File
            };

            entries.push(ContentEntry {
                path: file.name().to_string(),
                entry_type,
                offset: file.data_start(),
                size: file.size(),
                compressed_size: Some(file.compressed_size()),
                data: None,
            });
        }

        Ok(ParsedContent {
            format: ContentFormat::Archive(ArchiveType::Zip),
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: entries.len(),
                compression: Some("zip".to_string()),
                ..Default::default()
            },
            entries,
        })
    }

    fn format_name(&self) -> &'static str {
        "zip"
    }
}

/// Get all archive parsers
pub fn all_parsers() -> Vec<Box<dyn FormatParser>> {
    vec![
        Box::new(GzipParser),
        Box::new(Bzip2Parser),
        Box::new(XzParser),
        Box::new(ZstdParser),
        Box::new(TarParser),
        Box::new(ZipParser),
    ]
}

/// Extract data from tar archive at specific path
pub fn extract_tar_entry(data: &[u8], target_path: &str) -> ParseResult<Vec<u8>> {
    let mut archive = tar::Archive::new(Cursor::new(data));

    for entry in archive.entries().map_err(|e| ParseError::Archive(e.to_string()))? {
        let mut entry = entry.map_err(|e| ParseError::Archive(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| ParseError::Archive(e.to_string()))?
            .to_string_lossy()
            .to_string();

        if path == target_path {
            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .map_err(|e| ParseError::Io(e))?;
            return Ok(content);
        }
    }

    Err(ParseError::Archive(format!(
        "Entry not found: {}",
        target_path
    )))
}

/// Extract data from zip archive at specific path
pub fn extract_zip_entry(data: &[u8], target_path: &str) -> ParseResult<Vec<u8>> {
    let reader = Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|e| ParseError::Archive(e.to_string()))?;

    let mut file = archive
        .by_name(target_path)
        .map_err(|e| ParseError::Archive(e.to_string()))?;

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .map_err(|e| ParseError::Io(e))?;

    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gzip_parser() {
        let parser = GzipParser;
        // Minimal gzip header
        let data = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        assert!(parser.can_parse(&data));
    }

    #[test]
    fn test_zip_parser() {
        let parser = ZipParser;
        let data = [b'P', b'K', 0x03, 0x04, 0x00];
        assert!(parser.can_parse(&data));
    }
}
