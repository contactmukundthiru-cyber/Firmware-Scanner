//! Architecture detection for firmware binaries

use fw_parsers::elf::ElfParser;
use fw_parsers::pe::PeParser;
use fw_parsers::FormatParser;
use serde::{Deserialize, Serialize};

/// CPU architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CpuArchitecture {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    MipsLe,
    Mips64,
    PowerPc,
    PowerPc64,
    RiscV32,
    RiscV64,
    Sparc,
    SuperH,
    Xtensa,
    Arc,
    Unknown,
}

/// Byte order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
    Unknown,
}

/// Operating system fingerprint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsFingerprint {
    Linux { version: Option<String> },
    Android { version: Option<String> },
    FreeRTOS,
    VxWorks,
    QNX,
    ThreadX,
    Zephyr,
    NuttX,
    RIOT,
    Contiki,
    BareMetal,
    Windows,
    Unknown,
}

/// Complete architecture information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureInfo {
    pub cpu: CpuArchitecture,
    pub endianness: Endianness,
    pub word_size: u8,
    pub os: OsFingerprint,
    pub abi: Option<String>,
    pub toolchain: Option<String>,
}

/// Architecture detector
pub struct ArchitectureDetector {
    elf_parser: ElfParser,
    pe_parser: PeParser,
}

impl ArchitectureDetector {
    pub fn new() -> Self {
        Self {
            elf_parser: ElfParser::new(),
            pe_parser: PeParser::new(),
        }
    }

    /// Detect architecture from binary data
    pub fn detect(&self, data: &[u8]) -> Option<ArchitectureInfo> {
        // Try ELF first
        if self.elf_parser.can_parse(data) {
            return self.detect_from_elf(data);
        }

        // Try PE
        if self.pe_parser.can_parse(data) {
            return self.detect_from_pe(data);
        }

        None
    }

    fn detect_from_elf(&self, data: &[u8]) -> Option<ArchitectureInfo> {
        let analysis = self.elf_parser.analyze(data).ok()?;

        let cpu = match analysis.machine.as_str() {
            "x86" => CpuArchitecture::X86,
            "x86_64" => CpuArchitecture::X86_64,
            "ARM" => CpuArchitecture::Arm,
            "AArch64" => CpuArchitecture::Arm64,
            "MIPS" => {
                if analysis.endianness == fw_parsers::Endianness::Little {
                    CpuArchitecture::MipsLe
                } else {
                    CpuArchitecture::Mips
                }
            }
            "PowerPC" => CpuArchitecture::PowerPc,
            "PowerPC64" => CpuArchitecture::PowerPc64,
            "RISC-V" => {
                if analysis.word_size == 64 {
                    CpuArchitecture::RiscV64
                } else {
                    CpuArchitecture::RiscV32
                }
            }
            "SPARC" => CpuArchitecture::Sparc,
            "SuperH" => CpuArchitecture::SuperH,
            _ => CpuArchitecture::Unknown,
        };

        let endianness = match analysis.endianness {
            fw_parsers::Endianness::Little => Endianness::Little,
            fw_parsers::Endianness::Big => Endianness::Big,
        };

        // Detect OS from strings and symbols
        let os = self.detect_os_from_elf(&analysis, data);

        // Extract toolchain from GCC version string
        let toolchain = self.extract_toolchain_info(data);

        Some(ArchitectureInfo {
            cpu,
            endianness,
            word_size: analysis.word_size,
            os,
            abi: analysis.interpreter.map(|i| i.to_string()),
            toolchain,
        })
    }

    fn detect_from_pe(&self, data: &[u8]) -> Option<ArchitectureInfo> {
        let analysis = self.pe_parser.analyze(data).ok()?;

        let cpu = match analysis.machine.as_str() {
            "x86" => CpuArchitecture::X86,
            "x86_64" => CpuArchitecture::X86_64,
            "ARM" | "ARMv7" => CpuArchitecture::Arm,
            "ARM64" => CpuArchitecture::Arm64,
            _ => CpuArchitecture::Unknown,
        };

        Some(ArchitectureInfo {
            cpu,
            endianness: Endianness::Little, // PE is always little-endian
            word_size: if analysis.is_64bit { 64 } else { 32 },
            os: OsFingerprint::Windows,
            abi: Some(analysis.subsystem),
            toolchain: None,
        })
    }

    fn detect_os_from_elf(
        &self,
        analysis: &fw_parsers::elf::ElfAnalysis,
        data: &[u8],
    ) -> OsFingerprint {
        // Check interpreter
        if let Some(ref interp) = analysis.interpreter {
            if interp.contains("android") {
                return OsFingerprint::Android { version: None };
            }
            if interp.contains("ld-linux") || interp.contains("ld.so") {
                return OsFingerprint::Linux { version: None };
            }
        }

        // Check for RTOS markers
        let text = String::from_utf8_lossy(data);

        if text.contains("FreeRTOS") || text.contains("xTaskCreate") {
            return OsFingerprint::FreeRTOS;
        }
        if text.contains("VxWorks") {
            return OsFingerprint::VxWorks;
        }
        if text.contains("QNX") || text.contains("Neutrino") {
            return OsFingerprint::QNX;
        }
        if text.contains("ThreadX") {
            return OsFingerprint::ThreadX;
        }
        if text.contains("Zephyr") {
            return OsFingerprint::Zephyr;
        }
        if text.contains("NuttX") {
            return OsFingerprint::NuttX;
        }
        if text.contains("RIOT") {
            return OsFingerprint::RIOT;
        }
        if text.contains("Contiki") {
            return OsFingerprint::Contiki;
        }

        // Check for Linux kernel version string
        if text.contains("Linux version") {
            // Extract version
            let version = extract_linux_version(&text);
            return OsFingerprint::Linux { version };
        }

        // Check for common libc
        if text.contains("glibc") || text.contains("musl") || text.contains("uclibc") {
            return OsFingerprint::Linux { version: None };
        }

        // Check if it's a bare metal binary (no dynamic linking)
        if analysis.interpreter.is_none() && analysis.imported_libraries.is_empty() {
            return OsFingerprint::BareMetal;
        }

        OsFingerprint::Unknown
    }

    fn extract_toolchain_info(&self, data: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(data);

        // Look for GCC version string
        if let Some(start) = text.find("GCC:") {
            let end = text[start..].find('\0').unwrap_or(100);
            let version = &text[start..start + std::cmp::min(end, 100)];
            return Some(version.trim().to_string());
        }

        // Look for clang version
        if let Some(start) = text.find("clang version") {
            let end = text[start..].find('\0').unwrap_or(100);
            let version = &text[start..start + std::cmp::min(end, 100)];
            return Some(version.trim().to_string());
        }

        None
    }
}

impl Default for ArchitectureDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_linux_version(text: &str) -> Option<String> {
    if let Some(start) = text.find("Linux version ") {
        let after = &text[start + 14..];
        if let Some(end) = after.find(' ') {
            return Some(after[..end].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture_detector_creation() {
        let detector = ArchitectureDetector::new();
        // Should not panic
    }

    #[test]
    fn test_extract_linux_version() {
        let text = "Linux version 5.10.0-generic (builder@host)";
        assert_eq!(extract_linux_version(text), Some("5.10.0-generic".to_string()));
    }
}
