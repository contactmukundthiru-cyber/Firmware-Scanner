//! Firmware file format parsers
//!
//! This crate provides parsers for various firmware container formats,
//! filesystems, and executable formats.

pub mod archives;
pub mod containers;
pub mod elf;
pub mod filesystems;
pub mod magic;
pub mod pe;

use std::io::{Read, Seek};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid magic bytes at offset {offset}: expected {expected}, got {actual}")]
    InvalidMagic {
        offset: u64,
        expected: String,
        actual: String,
    },

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Truncated data: expected {expected} bytes, got {actual}")]
    TruncatedData { expected: usize, actual: usize },

    #[error("Invalid structure: {0}")]
    InvalidStructure(String),

    #[error("Decompression error: {0}")]
    Decompression(String),

    #[error("Archive error: {0}")]
    Archive(String),
}

pub type ParseResult<T> = Result<T, ParseError>;

/// Trait for parsers that can detect and extract from a format
pub trait FormatParser: Send + Sync {
    /// Check if the data matches this format
    fn can_parse(&self, data: &[u8]) -> bool;

    /// Parse and extract contents
    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent>;

    /// Human-readable format name
    fn format_name(&self) -> &'static str;
}

/// Represents parsed content from a container
#[derive(Debug, Clone)]
pub struct ParsedContent {
    pub format: ContentFormat,
    pub entries: Vec<ContentEntry>,
    pub metadata: ContentMetadata,
}

#[derive(Debug, Clone)]
pub enum ContentFormat {
    Archive(ArchiveType),
    Filesystem(FilesystemType),
    Executable(ExecutableType),
    Raw,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveType {
    Tar,
    Zip,
    Gzip,
    Bzip2,
    Xz,
    Lz4,
    Zstd,
    Cpio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemType {
    SquashFS,
    CramFS,
    Ext4,
    Ext2,
    JFFS2,
    YAFFS,
    YAFFS2,
    UBI,
    UBIFS,
    RomFS,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableType {
    Elf32Le,
    Elf32Be,
    Elf64Le,
    Elf64Be,
    Pe32,
    Pe64,
    MachO32,
    MachO64,
}

#[derive(Debug, Clone)]
pub struct ContentEntry {
    pub path: String,
    pub entry_type: EntryType,
    pub offset: u64,
    pub size: u64,
    pub compressed_size: Option<u64>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    File,
    Directory,
    Symlink,
    Device,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct ContentMetadata {
    pub total_size: u64,
    pub entry_count: usize,
    pub compression: Option<String>,
    pub endianness: Option<Endianness>,
    pub word_size: Option<u8>,
    pub extra: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

/// Read exact bytes with better error handling
pub fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> ParseResult<()> {
    let mut total_read = 0;
    while total_read < buf.len() {
        match reader.read(&mut buf[total_read..]) {
            Ok(0) => {
                return Err(ParseError::TruncatedData {
                    expected: buf.len(),
                    actual: total_read,
                });
            }
            Ok(n) => total_read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ParseError::Io(e)),
        }
    }
    Ok(())
}

/// Read bytes at a specific offset
pub fn read_at<R: Read + Seek>(reader: &mut R, offset: u64, len: usize) -> ParseResult<Vec<u8>> {
    use std::io::SeekFrom;
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    read_exact(reader, &mut buf)?;
    Ok(buf)
}
