//! PE/COFF binary parser with full import/export and section analysis

use crate::{
    ContentEntry, ContentFormat, ContentMetadata, Endianness, EntryType, ExecutableType,
    FormatParser, ParseError, ParseResult, ParsedContent,
};
use goblin::pe::PE;
use std::collections::HashMap;

/// Complete PE analysis result
#[derive(Debug, Clone)]
pub struct PeAnalysis {
    pub format: ExecutableType,
    pub machine: String,
    pub entry_point: u64,
    pub image_base: u64,
    pub is_dll: bool,
    pub is_64bit: bool,
    pub subsystem: String,
    pub timestamp: u32,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub exports: Vec<PeExport>,
    pub resources: Vec<PeResource>,
    pub debug_info: Option<PeDebugInfo>,
    pub strings: Vec<ExtractedString>,
    pub certificates: Vec<PeCertificate>,
}

#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub characteristics: u32,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
    pub entropy: f64,
}

#[derive(Debug, Clone)]
pub struct PeImport {
    pub dll_name: String,
    pub functions: Vec<ImportedFunction>,
}

#[derive(Debug, Clone)]
pub struct ImportedFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: u16,
}

#[derive(Debug, Clone)]
pub struct PeExport {
    pub name: Option<String>,
    pub ordinal: u32,
    pub address: u64,
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeResource {
    pub resource_type: String,
    pub name: String,
    pub language: u16,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct PeDebugInfo {
    pub debug_type: String,
    pub timestamp: u32,
    pub pdb_path: Option<String>,
    pub guid: Option<String>,
    pub age: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct PeCertificate {
    pub offset: u64,
    pub size: u64,
    pub revision: u16,
    pub cert_type: u16,
}

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub section: Option<String>,
    pub is_wide: bool,
}

pub struct PeParser;

impl PeParser {
    pub fn new() -> Self {
        Self
    }

    /// Perform full PE analysis
    pub fn analyze(&self, data: &[u8]) -> ParseResult<PeAnalysis> {
        let pe = PE::parse(data)
            .map_err(|e| ParseError::InvalidStructure(format!("PE parse error: {}", e)))?;

        let is_64bit = pe.is_64;
        let format = if is_64bit {
            ExecutableType::Pe64
        } else {
            ExecutableType::Pe32
        };

        let machine = machine_to_string(pe.header.coff_header.machine);
        let entry_point = pe
            .entry
            .checked_add(pe.image_base as usize)
            .unwrap_or(pe.entry) as u64;
        let image_base = pe.image_base as u64;
        let is_dll = pe.is_lib;

        let subsystem = pe
            .header
            .optional_header
            .as_ref()
            .map(|oh| subsystem_to_string(oh.windows_fields.subsystem))
            .unwrap_or_else(|| "Unknown".to_string());

        let timestamp = pe.header.coff_header.time_date_stamp;

        // Parse sections
        let sections: Vec<PeSection> = pe
            .sections
            .iter()
            .map(|s| {
                let name = String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string();

                let start = s.pointer_to_raw_data as usize;
                let end = std::cmp::min(start + s.size_of_raw_data as usize, data.len());
                let section_data = if start < end { &data[start..end] } else { &[] };
                let entropy = calculate_entropy(section_data);

                PeSection {
                    name,
                    virtual_address: s.virtual_address as u64,
                    virtual_size: s.virtual_size as u64,
                    raw_offset: s.pointer_to_raw_data as u64,
                    raw_size: s.size_of_raw_data as u64,
                    characteristics: s.characteristics,
                    is_executable: s.characteristics & 0x20000000 != 0,
                    is_writable: s.characteristics & 0x80000000 != 0,
                    is_readable: s.characteristics & 0x40000000 != 0,
                    entropy,
                }
            })
            .collect();

        // Parse imports
        let mut imports = Vec::new();
        for import in &pe.imports {
            let dll_name = import.dll.to_string();

            // Find existing or create new
            let existing = imports.iter_mut().find(|i: &&mut PeImport| i.dll_name == dll_name);
            if let Some(imp) = existing {
                imp.functions.push(ImportedFunction {
                    name: Some(import.name.to_string()),
                    ordinal: None,
                    hint: 0,
                });
            } else {
                imports.push(PeImport {
                    dll_name,
                    functions: vec![ImportedFunction {
                        name: Some(import.name.to_string()),
                        ordinal: None,
                        hint: 0,
                    }],
                });
            }
        }

        // Parse exports
        let exports: Vec<PeExport> = pe
            .exports
            .iter()
            .enumerate()
            .map(|(i, e)| {
                PeExport {
                    name: e.name.map(|s| s.to_string()),
                    ordinal: i as u32,
                    address: e.rva as u64,
                    forwarder: e.reexport.as_ref().map(|r| format!("{:?}", r)),
                }
            })
            .collect();

        // Extract strings
        let strings = self.extract_strings_from_pe(data, &sections);

        // Parse debug info
        let debug_info = parse_debug_info(&pe, data);

        // Parse certificates (authenticode)
        let certificates = parse_certificates(&pe, data);

        // Parse resources (simplified - full parsing would require more work)
        let resources = Vec::new(); // TODO: implement resource parsing

        Ok(PeAnalysis {
            format,
            machine,
            entry_point,
            image_base,
            is_dll,
            is_64bit,
            subsystem,
            timestamp,
            sections,
            imports,
            exports,
            resources,
            debug_info,
            strings,
            certificates,
        })
    }

    /// Extract strings from PE sections
    fn extract_strings_from_pe(&self, data: &[u8], sections: &[PeSection]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let min_length = 4;

        for section in sections {
            // Only extract from data sections, not code
            if section.name == ".rdata" || section.name == ".data" || section.name == ".rsrc" {
                let start = section.raw_offset as usize;
                let end = std::cmp::min(start + section.raw_size as usize, data.len());
                if start >= end {
                    continue;
                }

                let section_data = &data[start..end];

                // Extract ASCII strings
                strings.extend(extract_ascii_strings(
                    section_data,
                    start as u64,
                    min_length,
                    Some(section.name.clone()),
                ));

                // Extract wide (UTF-16) strings
                strings.extend(extract_wide_strings(
                    section_data,
                    start as u64,
                    min_length,
                    Some(section.name.clone()),
                ));
            }
        }

        strings
    }

    /// Get specific section data
    pub fn get_section_data<'a>(&self, data: &'a [u8], section_name: &str) -> ParseResult<Option<&'a [u8]>> {
        let pe = PE::parse(data)
            .map_err(|e| ParseError::InvalidStructure(format!("PE parse error: {}", e)))?;

        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();

            if name == section_name {
                let start = section.pointer_to_raw_data as usize;
                let end = start + section.size_of_raw_data as usize;
                if end <= data.len() {
                    return Ok(Some(&data[start..end]));
                }
            }
        }

        Ok(None)
    }

    /// Find imported functions by name patterns
    pub fn find_imports(&self, data: &[u8], patterns: &[&str]) -> ParseResult<Vec<(String, String)>> {
        let pe = PE::parse(data)
            .map_err(|e| ParseError::InvalidStructure(format!("PE parse error: {}", e)))?;

        let mut matches = Vec::new();

        for import in &pe.imports {
            for pattern in patterns {
                if import.name.to_lowercase().contains(&pattern.to_lowercase()) {
                    matches.push((import.dll.to_string(), import.name.to_string()));
                }
            }
        }

        Ok(matches)
    }
}

impl FormatParser for PeParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        if data.len() < 64 {
            return false;
        }
        // Check DOS header magic
        if &data[0..2] != &[b'M', b'Z'] {
            return false;
        }
        // Get PE header offset
        let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if pe_offset + 4 > data.len() {
            return false;
        }
        // Check PE signature
        &data[pe_offset..pe_offset + 4] == &[b'P', b'E', 0, 0]
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let analysis = self.analyze(data)?;

        let entries: Vec<ContentEntry> = analysis
            .sections
            .iter()
            .map(|s| ContentEntry {
                path: s.name.clone(),
                entry_type: EntryType::File,
                offset: s.raw_offset,
                size: s.raw_size,
                compressed_size: None,
                data: None,
            })
            .collect();

        let mut extra = HashMap::new();
        extra.insert("machine".to_string(), analysis.machine.clone());
        extra.insert("entry_point".to_string(), format!("0x{:x}", analysis.entry_point));
        extra.insert("image_base".to_string(), format!("0x{:x}", analysis.image_base));
        extra.insert("is_dll".to_string(), analysis.is_dll.to_string());
        extra.insert("subsystem".to_string(), analysis.subsystem.clone());
        extra.insert("timestamp".to_string(), analysis.timestamp.to_string());
        extra.insert("import_count".to_string(), analysis.imports.len().to_string());
        extra.insert("export_count".to_string(), analysis.exports.len().to_string());

        if let Some(ref debug) = analysis.debug_info {
            if let Some(ref pdb) = debug.pdb_path {
                extra.insert("pdb_path".to_string(), pdb.clone());
            }
        }

        Ok(ParsedContent {
            format: ContentFormat::Executable(analysis.format),
            entries,
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: analysis.sections.len(),
                compression: None,
                endianness: Some(Endianness::Little),
                word_size: Some(if analysis.is_64bit { 64 } else { 32 }),
                extra,
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "PE"
    }
}

fn machine_to_string(machine: u16) -> String {
    match machine {
        0x0 => "Unknown".to_string(),
        0x14c => "x86".to_string(),
        0x8664 => "x86_64".to_string(),
        0x1c0 => "ARM".to_string(),
        0xaa64 => "ARM64".to_string(),
        0x1c4 => "ARMv7".to_string(),
        0x5032 => "RISC-V 32".to_string(),
        0x5064 => "RISC-V 64".to_string(),
        _ => format!("Unknown(0x{:x})", machine),
    }
}

fn subsystem_to_string(subsystem: u16) -> String {
    match subsystem {
        0 => "Unknown".to_string(),
        1 => "Native".to_string(),
        2 => "Windows GUI".to_string(),
        3 => "Windows Console".to_string(),
        5 => "OS/2 Console".to_string(),
        7 => "POSIX Console".to_string(),
        9 => "Windows CE".to_string(),
        10 => "EFI Application".to_string(),
        11 => "EFI Boot Service Driver".to_string(),
        12 => "EFI Runtime Driver".to_string(),
        13 => "EFI ROM".to_string(),
        14 => "Xbox".to_string(),
        16 => "Windows Boot Application".to_string(),
        _ => format!("Unknown({})", subsystem),
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
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

fn extract_ascii_strings(
    data: &[u8],
    base_offset: u64,
    min_length: usize,
    section: Option<String>,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if byte >= 0x20 && byte < 0x7F {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(byte);
        } else if byte == 0 && current.len() >= min_length {
            if let Ok(s) = String::from_utf8(current.clone()) {
                strings.push(ExtractedString {
                    value: s,
                    offset: base_offset + start_offset as u64,
                    section: section.clone(),
                    is_wide: false,
                });
            }
            current.clear();
        } else {
            current.clear();
        }
    }

    strings
}

fn extract_wide_strings(
    data: &[u8],
    base_offset: u64,
    min_length: usize,
    section: Option<String>,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();

    if data.len() < 2 {
        return strings;
    }

    let mut current = Vec::new();
    let mut start_offset = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        let wchar = u16::from_le_bytes([data[i], data[i + 1]]);

        if wchar >= 0x20 && wchar < 0x7F {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(wchar as u8);
            i += 2;
        } else if wchar == 0 && current.len() >= min_length {
            if let Ok(s) = String::from_utf8(current.clone()) {
                strings.push(ExtractedString {
                    value: s,
                    offset: base_offset + start_offset as u64,
                    section: section.clone(),
                    is_wide: true,
                });
            }
            current.clear();
            i += 2;
        } else {
            current.clear();
            i += 2;
        }
    }

    strings
}

fn parse_debug_info(pe: &PE, _data: &[u8]) -> Option<PeDebugInfo> {
    // Check debug directory
    if let Some(ref debug_data) = pe.debug_data {
        if let Some(ref codeview) = debug_data.codeview_pdb70_debug_info {
            // Convert signature bytes to hex string
            let guid = codeview.signature
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>();

            // Convert filename bytes to string
            let pdb_path = String::from_utf8_lossy(codeview.filename).to_string();

            return Some(PeDebugInfo {
                debug_type: "CodeView PDB70".to_string(),
                timestamp: 0,
                pdb_path: Some(pdb_path),
                guid: Some(guid),
                age: Some(codeview.age),
            });
        }
    }

    None
}

fn parse_certificates(pe: &PE, _data: &[u8]) -> Vec<PeCertificate> {
    let mut certs = Vec::new();

    if let Some(ref optional) = pe.header.optional_header {
        if let Some(ref dd) = optional.data_directories.get_certificate_table() {
            certs.push(PeCertificate {
                offset: dd.virtual_address as u64,
                size: dd.size as u64,
                revision: 0,
                cert_type: 0,
            });
        }
    }

    certs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_detection() {
        let parser = PeParser::new();
        // Minimal PE header
        let mut data = vec![0u8; 0x100];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x80; // PE header offset
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        assert!(parser.can_parse(&data));
    }
}
