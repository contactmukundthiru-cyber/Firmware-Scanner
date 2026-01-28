//! Evidence export functionality

use super::{Evidence, EvidencePack};
use crate::CoreResult;
use std::fs;
use std::path::Path;

/// Export evidence to filesystem
pub fn export_to_directory(pack: &EvidencePack, dir: &Path) -> CoreResult<()> {
    fs::create_dir_all(dir)?;

    // Write JSON index
    let index_path = dir.join("evidence_index.json");
    let json = pack.to_json().map_err(|e| crate::CoreError::Evidence(e.to_string()))?;
    fs::write(&index_path, json)?;

    // Write individual evidence files
    let evidence_dir = dir.join("items");
    fs::create_dir_all(&evidence_dir)?;

    for evidence in &pack.evidence_items {
        let filename = format!("{}.json", evidence.id);
        let path = evidence_dir.join(&filename);
        let evidence_json = serde_json::to_string_pretty(&evidence)
            .map_err(|e| crate::CoreError::Evidence(e.to_string()))?;
        fs::write(&path, evidence_json)?;

        // Write raw matched data
        let raw_filename = format!("{}.bin", evidence.id);
        let raw_path = evidence_dir.join(&raw_filename);
        fs::write(&raw_path, &evidence.matched_data)?;
    }

    Ok(())
}

/// Format evidence for display
pub fn format_evidence_display(evidence: &Evidence) -> String {
    let mut output = String::new();

    output.push_str(&format!("Evidence ID: {}\n", evidence.id));
    output.push_str(&format!("Finding: {}\n", evidence.finding_id));
    output.push_str(&format!("File: {}\n", evidence.file_path));
    output.push_str(&format!("Offset: 0x{:x} ({} bytes)\n", evidence.byte_offset, evidence.byte_length));
    output.push_str(&format!("Hash: {}\n", evidence.content_hash));
    output.push_str("\n--- Context ---\n");

    // Format hex dump with context
    let full_context = evidence.full_context();
    for (i, chunk) in full_context.chunks(16).enumerate() {
        let offset = i * 16;
        output.push_str(&format!("{:08x}  ", evidence.byte_offset as usize - evidence.context_before.len() + offset));

        // Hex
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                output.push(' ');
            }
            output.push_str(&format!("{:02x} ", byte));
        }

        // Padding
        for _ in chunk.len()..16 {
            output.push_str("   ");
        }
        if chunk.len() <= 8 {
            output.push(' ');
        }

        output.push_str(" |");

        // ASCII
        for byte in chunk {
            if *byte >= 0x20 && *byte < 0x7F {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }

        output.push_str("|\n");
    }

    output.push_str("\n--- Reproduction ---\n");
    output.push_str(&evidence.reproduction_notes);
    output.push('\n');

    output
}
