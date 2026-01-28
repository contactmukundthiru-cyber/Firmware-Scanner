//! Report generation routes

use crate::AppState;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use sqlx::Row;

#[derive(Deserialize)]
pub struct ReportQuery {
    pub format: Option<String>,
}

#[derive(Serialize)]
pub struct ReportResponse {
    pub scan_id: Uuid,
    pub format: String,
    pub content: String,
}

pub async fn get_report(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<Json<ReportResponse>, StatusCode> {
    let format = query.format.unwrap_or_else(|| "markdown".to_string());

    // Get scan result from database
    let row = sqlx::query(
        "SELECT name, status, artifact_hash, completed_at FROM scans WHERE id = $1"
    )
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let status: String = row.get("status");
    if status != "completed" {
        return Err(StatusCode::NOT_FOUND);
    }

    let name: String = row.get("name");
    let artifact_hash: Option<String> = row.get("artifact_hash");
    let completed_at: Option<chrono::DateTime<chrono::Utc>> = row.get("completed_at");

    // Generate simple report
    let content = format!(
        r#"# Firmware Scan Report

**Scan ID:** {}
**Name:** {}
**Status:** {}
**Artifact Hash:** {}
**Completed:** {}

## Summary

Scan completed successfully.
"#,
        id,
        name,
        status,
        artifact_hash.unwrap_or_else(|| "N/A".to_string()),
        completed_at.map(|t| t.to_string()).unwrap_or_else(|| "N/A".to_string())
    );

    Ok(Json(ReportResponse {
        scan_id: id,
        format,
        content,
    }))
}

pub async fn download_report(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<Response, StatusCode> {
    let format = query.format.unwrap_or_else(|| "markdown".to_string());

    let report = get_report(State(state), Path(id), Query(ReportQuery { format: Some(format.clone()) }))
        .await?
        .0;

    let (content_type, extension) = match format.as_str() {
        "json" => ("application/json", "json"),
        "html" => ("text/html", "html"),
        _ => ("text/markdown", "md"),
    };

    let filename = format!("firmware_report_{}.{}", id, extension);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(report.content))
        .unwrap())
}
