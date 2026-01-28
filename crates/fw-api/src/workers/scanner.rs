//! Background scan worker

use crate::AppState;
use std::sync::Arc;
use tracing::{info, error};
use uuid::Uuid;
use sqlx::Row;

pub async fn run_scan(state: Arc<AppState>, scan_id: Uuid, file_path: String) {
    info!("Starting scan {} for file {}", scan_id, file_path);

    // Update status to running
    let _ = sqlx::query("UPDATE scans SET status = 'running' WHERE id = $1")
        .bind(scan_id)
        .execute(&state.db)
        .await;

    // Read file
    let data = match tokio::fs::read(&file_path).await {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to read file: {}", e);
            let _ = sqlx::query("UPDATE scans SET status = 'failed' WHERE id = $1")
                .bind(scan_id)
                .execute(&state.db)
                .await;
            return;
        }
    };

    // Run scan
    match state.scanner.scan_bytes(&data, Some(file_path.clone())) {
        Ok(result) => {
            info!("Scan {} completed with {} findings",
                scan_id, result.summary.total_capabilities_found);

            // Update scan record
            let _ = sqlx::query(
                "UPDATE scans SET status = 'completed', completed_at = NOW(), artifact_hash = $2 WHERE id = $1"
            )
                .bind(scan_id)
                .bind(&result.artifact.hash)
                .execute(&state.db)
                .await;

            // Insert findings
            for finding in &result.analysis.all_findings {
                let evidence_json = serde_json::to_value(&finding).unwrap_or_default();
                let _ = sqlx::query(
                    "INSERT INTO findings (id, scan_id, capability_type, severity, is_dormant, evidence_json, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())"
                )
                    .bind(Uuid::new_v4())
                    .bind(scan_id)
                    .bind(finding.capability_type.to_string())
                    .bind(finding.severity.to_string())
                    .bind(finding.is_dormant)
                    .bind(&evidence_json)
                    .execute(&state.db)
                    .await;
            }

            // Insert claim verdicts
            for verdict in &result.claim_verdicts {
                let evidence_ids: Vec<Uuid> = verdict.evidence.iter().map(|e| e.id).collect();
                let failing_json = serde_json::to_value(&verdict.failing_conditions).ok();
                let compatible_str = match verdict.compatible {
                    fw_core::TriState::Yes => "yes",
                    fw_core::TriState::No => "no",
                    fw_core::TriState::Indeterminate => "indeterminate",
                };
                let _ = sqlx::query(
                    "INSERT INTO claim_verdicts (id, scan_id, claim_type, compatible, failing_conditions, evidence_ids) VALUES ($1, $2, $3, $4, $5, $6)"
                )
                    .bind(Uuid::new_v4())
                    .bind(scan_id)
                    .bind(verdict.claim.name())
                    .bind(compatible_str)
                    .bind(&failing_json)
                    .bind(&evidence_ids)
                    .execute(&state.db)
                    .await;
            }

            // Insert evidence
            for evidence in &result.evidence {
                let _ = sqlx::query(
                    "INSERT INTO evidence_artifacts (id, scan_id, file_path, byte_offset, byte_length, content_hash, context_data, reproduction_script) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
                )
                    .bind(evidence.id)
                    .bind(scan_id)
                    .bind(&evidence.file_path)
                    .bind(evidence.byte_offset as i64)
                    .bind(evidence.byte_length as i64)
                    .bind(&evidence.content_hash)
                    .bind(&evidence.matched_data[..])
                    .bind(&evidence.reproduction_notes)
                    .execute(&state.db)
                    .await;
            }
        }
        Err(e) => {
            error!("Scan {} failed: {}", scan_id, e);
            let _ = sqlx::query("UPDATE scans SET status = 'failed' WHERE id = $1")
                .bind(scan_id)
                .execute(&state.db)
                .await;
        }
    }
}
