//! Dormant capability detector

use super::DormantCapability;
use crate::analysis::{AnalysisResult, CapabilityType};
use crate::ingestion::FirmwareArtifact;

/// Detect dormant capabilities in firmware
pub fn detect_dormant(
    artifact: &FirmwareArtifact,
    raw_data: &[u8],
    analysis: &AnalysisResult,
) -> Vec<DormantCapability> {
    let mut dormant = Vec::new();
    let text = String::from_utf8_lossy(raw_data);

    // Look for conditional code patterns
    dormant.extend(detect_feature_flags(&text));
    dormant.extend(detect_debug_code(&text));
    dormant.extend(detect_environment_gating(&text));
    dormant.extend(detect_region_locking(&text));
    dormant.extend(detect_compile_time_toggles(&text, raw_data));

    dormant
}

fn detect_feature_flags(text: &str) -> Vec<DormantCapability> {
    let mut dormant = Vec::new();

    // Feature flag patterns
    let patterns = [
        ("FEATURE_", "Compile-time feature flag"),
        ("ENABLE_", "Enable flag"),
        ("DISABLE_", "Disable flag"),
        ("CONFIG_", "Configuration option"),
        ("__DEBUG__", "Debug mode flag"),
        ("__RELEASE__", "Release mode flag"),
        ("DEMO_MODE", "Demo mode"),
        ("TEST_MODE", "Test mode"),
    ];

    for (pattern, desc) in patterns {
        if text.contains(pattern) {
            dormant.push(
                DormantCapability::new(
                    &format!("dormant-flag-{}", pattern.to_lowercase().replace("_", "-")),
                    CapabilityType::Update,
                    &format!("Feature Flag: {}", pattern),
                    &format!("Dormant capability gated by {} - {}", pattern, desc),
                )
                .with_conditions(vec![
                    format!("Flag {} must be set/enabled", pattern),
                ])
                .with_confidence(0.7),
            );
        }
    }

    dormant
}

fn detect_debug_code(text: &str) -> Vec<DormantCapability> {
    let mut dormant = Vec::new();

    // Debug interface patterns
    if text.contains("gdbserver") || text.contains("gdb_stub") {
        dormant.push(
            DormantCapability::new(
                "dormant-gdb",
                CapabilityType::Update,
                "GDB Debug Interface",
                "GDB server code present but may be inactive",
            )
            .with_conditions(vec![
                "Debug build or flag enabled".to_string(),
                "GDB port opened".to_string(),
            ])
            .with_confidence(0.8),
        );
    }

    if text.contains("telnetd") && !text.contains("telnetd=off") {
        dormant.push(
            DormantCapability::new(
                "dormant-telnet",
                CapabilityType::Networking,
                "Telnet Server",
                "Telnet daemon code present - potential remote access",
            )
            .with_conditions(vec![
                "Telnet service enabled".to_string(),
                "Network available".to_string(),
            ])
            .with_confidence(0.8),
        );
    }

    if text.contains("console=") || text.contains("uart_console") {
        dormant.push(
            DormantCapability::new(
                "dormant-uart",
                CapabilityType::Update,
                "UART Console",
                "Serial console code present",
            )
            .with_conditions(vec![
                "Serial port connected".to_string(),
                "Console enabled in bootargs".to_string(),
            ])
            .with_confidence(0.7),
        );
    }

    dormant
}

fn detect_environment_gating(text: &str) -> Vec<DormantCapability> {
    let mut dormant = Vec::new();

    // Environment variable gating
    let env_patterns = [
        ("getenv", "Environment variable check"),
        ("setenv", "Environment variable modification"),
        ("env_get", "Environment getter"),
        ("__environ", "Environment access"),
    ];

    for (pattern, desc) in env_patterns {
        if text.contains(pattern) {
            dormant.push(
                DormantCapability::new(
                    &format!("dormant-env-{}", pattern.replace("_", "-")),
                    CapabilityType::Update,
                    &format!("Environment Gating: {}", pattern),
                    &format!("Code path gated by environment - {}", desc),
                )
                .with_conditions(vec![
                    "Specific environment variable set".to_string(),
                ])
                .with_confidence(0.6),
            );
            break; // Only report once
        }
    }

    dormant
}

fn detect_region_locking(text: &str) -> Vec<DormantCapability> {
    let mut dormant = Vec::new();

    // Region-based feature gating
    let regions = ["US", "EU", "CN", "JP", "KR", "region", "country", "locale"];

    for region in regions {
        let pattern = format!("region_{}", region.to_lowercase());
        if text.to_lowercase().contains(&pattern) || text.contains(&format!("REGION_{}", region.to_uppercase())) {
            dormant.push(
                DormantCapability::new(
                    "dormant-region",
                    CapabilityType::Update,
                    "Region-Locked Feature",
                    "Features that vary by geographic region",
                )
                .with_conditions(vec![
                    "Device region setting".to_string(),
                    "Geographic location".to_string(),
                ])
                .with_confidence(0.7),
            );
            break;
        }
    }

    dormant
}

fn detect_compile_time_toggles(text: &str, data: &[u8]) -> Vec<DormantCapability> {
    let mut dormant = Vec::new();

    // Preprocessor-like patterns that suggest compile-time toggling
    if text.contains("#if 0") || text.contains("// #define") || text.contains("/* #define") {
        dormant.push(
            DormantCapability::new(
                "dormant-commented-code",
                CapabilityType::Update,
                "Commented Code",
                "Commented-out code that could be re-enabled",
            )
            .with_conditions(vec![
                "Code uncommenting".to_string(),
                "Recompilation".to_string(),
            ])
            .with_confidence(0.5),
        );
    }

    // Look for dead code (linked but not called)
    // This is a simplified check - real detection would need control flow analysis
    if text.contains("__attribute__((unused))") || text.contains("UNUSED_FUNCTION") {
        dormant.push(
            DormantCapability::new(
                "dormant-unused-code",
                CapabilityType::Update,
                "Unused Code",
                "Functions marked as unused but still linked",
            )
            .with_conditions(vec![
                "Direct function call".to_string(),
                "Function pointer usage".to_string(),
            ])
            .with_confidence(0.6),
        );
    }

    dormant
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_flag_detection() {
        let text = "checking FEATURE_TELEMETRY and CONFIG_DEBUG";
        let dormant = detect_feature_flags(text);
        assert!(!dormant.is_empty());
    }

    #[test]
    fn test_debug_code_detection() {
        let text = "initializing gdbserver on port 1234";
        let dormant = detect_debug_code(text);
        assert!(dormant.iter().any(|d| d.id == "dormant-gdb"));
    }
}
