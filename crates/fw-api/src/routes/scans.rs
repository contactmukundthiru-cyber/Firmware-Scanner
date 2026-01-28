//! Scan management routes

use crate::AppState;
use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Serialize)]
pub struct ScanResponse {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub created_at: String,
    pub artifact_hash: Option<String>,
    pub findings_count: i64,
}

#[derive(Serialize)]
pub struct ScanListResponse {
    pub scans: Vec<ScanResponse>,
    pub total: i64,
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateScanResponse {
    pub id: Uuid,
    pub message: String,
}

pub async fn create_scan(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<CreateScanResponse>, StatusCode> {
    let scan_id = Uuid::new_v4();
    let mut file_data = Vec::new();
    let mut file_name = String::new();

    // Process multipart form
    while let Some(field) = multipart.next_field().await.map_err(|_| StatusCode::BAD_REQUEST)? {
        if field.name() == Some("file") {
            file_name = field.file_name().unwrap_or("firmware.bin").to_string();
            file_data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?.to_vec();
        }
    }

    if file_data.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Save to disk
    let file_path = format!("{}/{}", state.config.upload_dir, scan_id);
    tokio::fs::write(&file_path, &file_data)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create scan record
    sqlx::query!(
        r#"
        INSERT INTO scans (id, name, status, created_at, artifact_size, config)
        VALUES ($1, $2, 'pending', NOW(), $3, '{}')
        "#,
        scan_id,
        file_name,
        file_data.len() as i64
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Spawn background scan task
    let state_clone = state.clone();
    tokio::spawn(async move {
        crate::workers::run_scan(state_clone, scan_id, file_path).await;
    });

    Ok(Json(CreateScanResponse {
        id: scan_id,
        message: "Scan started".to_string(),
    }))
}

pub async fn list_scans(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ScanListResponse>, StatusCode> {
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = (query.page.unwrap_or(1) - 1) * limit;

    let scans = sqlx::query_as!(
        ScanRecord,
        r#"
        SELECT id, name, status, created_at, artifact_hash,
               (SELECT COUNT(*) FROM findings WHERE scan_id = scans.id) as findings_count
        FROM scans
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
        limit,
        offset
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total = sqlx::query_scalar!("SELECT COUNT(*) FROM scans")
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or(0);

    let scans = scans
        .into_iter()
        .map(|s| ScanResponse {
            id: s.id,
            name: s.name,
            status: s.status,
            created_at: s.created_at.to_string(),
            artifact_hash: s.artifact_hash,
            findings_count: s.findings_count.unwrap_or(0),
        })
        .collect();

    Ok(Json(ScanListResponse { scans, total }))
}

pub async fn get_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanResponse>, StatusCode> {
    let scan = sqlx::query_as!(
        ScanRecord,
        r#"
        SELECT id, name, status, created_at, artifact_hash,
               (SELECT COUNT(*) FROM findings WHERE scan_id = scans.id) as findings_count
        FROM scans WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(ScanResponse {
        id: scan.id,
        name: scan.name,
        status: scan.status,
        created_at: scan.created_at.to_string(),
        artifact_hash: scan.artifact_hash,
        findings_count: scan.findings_count.unwrap_or(0),
    }))
}

pub async fn delete_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query!("DELETE FROM scans WHERE id = $1", id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Delete file
    let file_path = format!("{}/{}", state.config.upload_dir, id);
    let _ = tokio::fs::remove_file(&file_path).await;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_findings(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let findings = sqlx::query_scalar!(
        r#"SELECT evidence_json FROM findings WHERE scan_id = $1"#,
        id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let findings: Vec<serde_json::Value> = findings
        .into_iter()
        .filter_map(|f| f)
        .collect();

    Ok(Json(findings))
}

pub async fn get_claims(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let claims = sqlx::query_scalar!(
        r#"SELECT failing_conditions FROM claim_verdicts WHERE scan_id = $1"#,
        id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let claims: Vec<serde_json::Value> = claims
        .into_iter()
        .filter_map(|c| c)
        .collect();

    Ok(Json(claims))
}

pub async fn get_evidence(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let evidence = sqlx::query_scalar!(
        r#"SELECT context_data FROM evidence_artifacts WHERE scan_id = $1"#,
        id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Convert bytes to base64 for JSON
    let evidence: Vec<serde_json::Value> = evidence
        .into_iter()
        .filter_map(|e| e.map(|data| serde_json::json!({ "data": hex::encode(data) })))
        .collect();

    Ok(Json(evidence))
}

struct ScanRecord {
    id: Uuid,
    name: String,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    artifact_hash: Option<String>,
    findings_count: Option<i64>,
}
