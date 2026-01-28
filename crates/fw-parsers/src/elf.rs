//! ELF binary parser with full symbol and section extraction

use crate::{
    ContentEntry, ContentFormat, ContentMetadata, Endianness, EntryType, ExecutableType,
    FormatParser, ParseError, ParseResult, ParsedContent,
};
use goblin::elf::{Elf, SectionHeader, Sym};
use std::collections::HashMap;

/// Complete ELF analysis result
#[derive(Debug, Clone)]
pub struct ElfAnalysis {
    pub format: ExecutableType,
    pub machine: String,
    pub entry_point: u64,
    pub endianness: Endianness,
    pub word_size: u8,
    pub is_pie: bool,
    pub is_stripped: bool,
    pub has_debug: bool,
    pub interpreter: Option<String>,
    pub sections: Vec<ElfSection>,
    pub symbols: Vec<ElfSymbol>,
    pub dynamic_symbols: Vec<ElfSymbol>,
    pub imported_libraries: Vec<String>,
    pub exported_functions: Vec<String>,
    pub strings: Vec<ExtractedString>,
    pub relocations: Vec<ElfRelocation>,
}

#[derive(Debug, Clone)]
pub struct ElfSection {
    pub name: String,
    pub section_type: String,
    pub offset: u64,
    pub size: u64,
    pub address: u64,
    pub flags: u64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_allocated: bool,
}

#[derive(Debug, Clone)]
pub struct ElfSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub symbol_type: String,
    pub binding: String,
    pub section_index: usize,
    pub is_function: bool,
    pub is_object: bool,
    pub is_undefined: bool,
}

#[derive(Debug, Clone)]
pub struct ElfRelocation {
    pub offset: u64,
    pub symbol_name: Option<String>,
    pub relocation_type: u32,
    pub addend: i64,
}

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub section: Option<String>,
}

pub struct ElfParser;

impl ElfParser {
    pub fn new() -> Self {
        Self
    }

    /// Perform full ELF analysis
    pub fn analyze(&self, data: &[u8]) -> ParseResult<ElfAnalysis> {
        let elf = Elf::parse(data)
            .map_err(|e| ParseError::InvalidStructure(format!("ELF parse error: {}", e)))?;

        let format = match (elf.is_64, elf.little_endian) {
            (false, true) => ExecutableType::Elf32Le,
            (false, false) => ExecutableType::Elf32Be,
            (true, true) => ExecutableType::Elf64Le,
            (true, false) => ExecutableType::Elf64Be,
        };

        let endianness = if elf.little_endian {
            Endianness::Little
        } else {
            Endianness::Big
        };

        let machine = machine_to_string(elf.header.e_machine);
        let entry_point = elf.entry;
        let word_size = if elf.is_64 { 64 } else { 32 };

        // Check if PIE (Position Independent Executable)
        let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN
            && elf.interpreter.is_some();

        // Check if stripped
        let is_stripped = elf.syms.is_empty();

        // Check for debug info
        let has_debug = elf
            .section_headers
            .iter()
            .any(|s| section_name(&elf, s).starts_with(".debug"));

        // Get interpreter
        let interpreter = elf.interpreter.map(|s| s.to_string());

        // Parse sections
        let sections: Vec<ElfSection> = elf
            .section_headers
            .iter()
            .map(|sh| {
                let name = section_name(&elf, sh);
                ElfSection {
                    name,
                    section_type: section_type_to_string(sh.sh_type),
                    offset: sh.sh_offset,
                    size: sh.sh_size,
                    address: sh.sh_addr,
                    flags: sh.sh_flags,
                    is_executable: sh.is_executable(),
                    is_writable: sh.is_writable(),
                    is_allocated: sh.is_alloc(),
                }
            })
            .collect();

        // Parse symbols
        let symbols: Vec<ElfSymbol> = elf
            .syms
            .iter()
            .map(|sym| symbol_to_struct(&elf, sym))
            .collect();

        // Parse dynamic symbols
        let dynamic_symbols: Vec<ElfSymbol> = elf
            .dynsyms
            .iter()
            .map(|sym| symbol_to_struct(&elf, sym))
            .collect();

        // Extract imported libraries
        let imported_libraries: Vec<String> = elf
            .libraries
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Extract exported functions
        let exported_functions: Vec<String> = dynamic_symbols
            .iter()
            .filter(|s| s.is_function && !s.is_undefined && !s.name.is_empty())
            .map(|s| s.name.clone())
            .collect();

        // Extract strings from relevant sections
        let strings = extract_strings(data, &elf);

        // Parse relocations
        let relocations = parse_relocations(&elf);

        Ok(ElfAnalysis {
            format,
            machine,
            entry_point,
            endianness,
            word_size,
            is_pie,
            is_stripped,
            has_debug,
            interpreter,
            sections,
            symbols,
            dynamic_symbols,
            imported_libraries,
            exported_functions,
            strings,
            relocations,
        })
    }

    /// Extract all strings from the binary
    pub fn extract_all_strings(&self, data: &[u8], min_length: usize) -> Vec<ExtractedString> {
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
                        offset: start_offset as u64,
                        section: None,
                    });
                }
                current.clear();
            } else {
                current.clear();
            }
        }

        strings
    }

    /// Get specific section data
    pub fn get_section_data<'a>(&self, data: &'a [u8], section_name: &str) -> ParseResult<Option<&'a [u8]>> {
        let elf = Elf::parse(data)
            .map_err(|e| ParseError::InvalidStructure(format!("ELF parse error: {}", e)))?;

        for sh in &elf.section_headers {
            let name = self::section_name(&elf, sh);
            if name == section_name {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                if end <= data.len() {
                    return Ok(Some(&data[start..end]));
                }
            }
        }

        Ok(None)
    }

    /// Find all function calls to specific functions
    pub fn find_function_references(&self, data: &[u8], function_names: &[&str]) -> ParseResult<Vec<(String, u64)>> {
        let elf = Elf::parse(data)
            .map_err(|e| ParseError::InvalidStructure(format!("ELF parse error: {}", e)))?;

        let mut references = Vec::new();

        // Check dynamic symbol references via relocations
        for reloc in &elf.dynrels {
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if function_names.contains(&name) {
                        references.push((name.to_string(), reloc.r_offset));
                    }
                }
            }
        }

        // Check PLT relocations
        for reloc in &elf.pltrelocs {
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if function_names.contains(&name) {
                        references.push((name.to_string(), reloc.r_offset));
                    }
                }
            }
        }

        Ok(references)
    }
}

impl FormatParser for ElfParser {
    fn can_parse(&self, data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == &[0x7F, b'E', b'L', b'F']
    }

    fn parse(&self, data: &[u8]) -> ParseResult<ParsedContent> {
        let analysis = self.analyze(data)?;

        let entries: Vec<ContentEntry> = analysis
            .sections
            .iter()
            .map(|s| ContentEntry {
                path: s.name.clone(),
                entry_type: EntryType::File,
                offset: s.offset,
                size: s.size,
                compressed_size: None,
                data: None,
            })
            .collect();

        let mut extra = HashMap::new();
        extra.insert("machine".to_string(), analysis.machine.clone());
        extra.insert("entry_point".to_string(), format!("0x{:x}", analysis.entry_point));
        extra.insert("is_pie".to_string(), analysis.is_pie.to_string());
        extra.insert("is_stripped".to_string(), analysis.is_stripped.to_string());
        extra.insert("has_debug".to_string(), analysis.has_debug.to_string());
        extra.insert("symbol_count".to_string(), analysis.symbols.len().to_string());
        extra.insert("dynsym_count".to_string(), analysis.dynamic_symbols.len().to_string());
        extra.insert("library_count".to_string(), analysis.imported_libraries.len().to_string());

        if let Some(ref interp) = analysis.interpreter {
            extra.insert("interpreter".to_string(), interp.clone());
        }

        Ok(ParsedContent {
            format: ContentFormat::Executable(analysis.format),
            entries,
            metadata: ContentMetadata {
                total_size: data.len() as u64,
                entry_count: analysis.sections.len(),
                compression: None,
                endianness: Some(analysis.endianness),
                word_size: Some(analysis.word_size),
                extra,
            },
        })
    }

    fn format_name(&self) -> &'static str {
        "ELF"
    }
}

fn section_name(elf: &Elf, sh: &SectionHeader) -> String {
    elf.shdr_strtab
        .get_at(sh.sh_name)
        .unwrap_or("<unknown>")
        .to_string()
}

fn section_type_to_string(t: u32) -> String {
    match t {
        goblin::elf::section_header::SHT_NULL => "NULL".to_string(),
        goblin::elf::section_header::SHT_PROGBITS => "PROGBITS".to_string(),
        goblin::elf::section_header::SHT_SYMTAB => "SYMTAB".to_string(),
        goblin::elf::section_header::SHT_STRTAB => "STRTAB".to_string(),
        goblin::elf::section_header::SHT_RELA => "RELA".to_string(),
        goblin::elf::section_header::SHT_HASH => "HASH".to_string(),
        goblin::elf::section_header::SHT_DYNAMIC => "DYNAMIC".to_string(),
        goblin::elf::section_header::SHT_NOTE => "NOTE".to_string(),
        goblin::elf::section_header::SHT_NOBITS => "NOBITS".to_string(),
        goblin::elf::section_header::SHT_REL => "REL".to_string(),
        goblin::elf::section_header::SHT_DYNSYM => "DYNSYM".to_string(),
        goblin::elf::section_header::SHT_INIT_ARRAY => "INIT_ARRAY".to_string(),
        goblin::elf::section_header::SHT_FINI_ARRAY => "FINI_ARRAY".to_string(),
        goblin::elf::section_header::SHT_GNU_HASH => "GNU_HASH".to_string(),
        goblin::elf::section_header::SHT_GNU_VERDEF => "GNU_VERDEF".to_string(),
        goblin::elf::section_header::SHT_GNU_VERNEED => "GNU_VERNEED".to_string(),
        goblin::elf::section_header::SHT_GNU_VERSYM => "GNU_VERSYM".to_string(),
        _ => format!("UNKNOWN(0x{:x})", t),
    }
}

fn machine_to_string(machine: u16) -> String {
    match machine {
        goblin::elf::header::EM_NONE => "None".to_string(),
        goblin::elf::header::EM_386 => "x86".to_string(),
        goblin::elf::header::EM_X86_64 => "x86_64".to_string(),
        goblin::elf::header::EM_ARM => "ARM".to_string(),
        goblin::elf::header::EM_AARCH64 => "AArch64".to_string(),
        goblin::elf::header::EM_MIPS => "MIPS".to_string(),
        goblin::elf::header::EM_PPC => "PowerPC".to_string(),
        goblin::elf::header::EM_PPC64 => "PowerPC64".to_string(),
        goblin::elf::header::EM_RISCV => "RISC-V".to_string(),
        goblin::elf::header::EM_SPARC => "SPARC".to_string(),
        goblin::elf::header::EM_SH => "SuperH".to_string(),
        _ => format!("Unknown({})", machine),
    }
}

fn symbol_type_to_string(st_type: u8) -> String {
    match st_type {
        goblin::elf::sym::STT_NOTYPE => "NOTYPE".to_string(),
        goblin::elf::sym::STT_OBJECT => "OBJECT".to_string(),
        goblin::elf::sym::STT_FUNC => "FUNC".to_string(),
        goblin::elf::sym::STT_SECTION => "SECTION".to_string(),
        goblin::elf::sym::STT_FILE => "FILE".to_string(),
        goblin::elf::sym::STT_COMMON => "COMMON".to_string(),
        goblin::elf::sym::STT_TLS => "TLS".to_string(),
        _ => format!("UNKNOWN({})", st_type),
    }
}

fn binding_to_string(st_bind: u8) -> String {
    match st_bind {
        goblin::elf::sym::STB_LOCAL => "LOCAL".to_string(),
        goblin::elf::sym::STB_GLOBAL => "GLOBAL".to_string(),
        goblin::elf::sym::STB_WEAK => "WEAK".to_string(),
        _ => format!("UNKNOWN({})", st_bind),
    }
}

fn symbol_to_struct(elf: &Elf, sym: &Sym) -> ElfSymbol {
    let name = elf
        .strtab
        .get_at(sym.st_name)
        .or_else(|| elf.dynstrtab.get_at(sym.st_name))
        .unwrap_or("")
        .to_string();

    ElfSymbol {
        name,
        address: sym.st_value,
        size: sym.st_size,
        symbol_type: symbol_type_to_string(sym.st_type()),
        binding: binding_to_string(sym.st_bind()),
        section_index: sym.st_shndx,
        is_function: sym.st_type() == goblin::elf::sym::STT_FUNC,
        is_object: sym.st_type() == goblin::elf::sym::STT_OBJECT,
        is_undefined: sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize,
    }
}

fn extract_strings(data: &[u8], elf: &Elf) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let min_length = 4;

    // Extract from string sections
    for sh in &elf.section_headers {
        let name = section_name(elf, sh);
        if name.contains("str") || name == ".rodata" || name == ".data" {
            let start = sh.sh_offset as usize;
            let end = std::cmp::min(start + sh.sh_size as usize, data.len());
            if start < end {
                let section_data = &data[start..end];
                let mut current = Vec::new();
                let mut str_start = 0;

                for (i, &byte) in section_data.iter().enumerate() {
                    if byte >= 0x20 && byte < 0x7F {
                        if current.is_empty() {
                            str_start = i;
                        }
                        current.push(byte);
                    } else if byte == 0 && current.len() >= min_length {
                        if let Ok(s) = String::from_utf8(current.clone()) {
                            strings.push(ExtractedString {
                                value: s,
                                offset: (start + str_start) as u64,
                                section: Some(name.clone()),
                            });
                        }
                        current.clear();
                    } else {
                        current.clear();
                    }
                }
            }
        }
    }

    strings
}

fn parse_relocations(elf: &Elf) -> Vec<ElfRelocation> {
    let mut relocs = Vec::new();

    for reloc in &elf.dynrels {
        let sym_name = elf.dynsyms.get(reloc.r_sym).and_then(|sym| {
            elf.dynstrtab.get_at(sym.st_name).map(|s| s.to_string())
        });

        relocs.push(ElfRelocation {
            offset: reloc.r_offset,
            symbol_name: sym_name,
            relocation_type: reloc.r_type,
            addend: reloc.r_addend.unwrap_or(0),
        });
    }

    for reloc in &elf.pltrelocs {
        let sym_name = elf.dynsyms.get(reloc.r_sym).and_then(|sym| {
            elf.dynstrtab.get_at(sym.st_name).map(|s| s.to_string())
        });

        relocs.push(ElfRelocation {
            offset: reloc.r_offset,
            symbol_name: sym_name,
            relocation_type: reloc.r_type,
            addend: reloc.r_addend.unwrap_or(0),
        });
    }

    relocs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_detection() {
        let parser = ElfParser::new();
        let elf_magic = [0x7F, b'E', b'L', b'F'];
        assert!(parser.can_parse(&elf_magic));
        assert!(!parser.can_parse(&[0x00, 0x00, 0x00, 0x00]));
    }
}
