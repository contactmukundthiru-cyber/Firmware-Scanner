//! Admin routes

use crate::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct StatsResponse {
    pub total_scans: i64,
    pub completed_scans: i64,
    pub failed_scans: i64,
    pub pending_scans: i64,
    pub total_findings: i64,
}

#[derive(Serialize)]
pub struct ConfigResponse {
    pub max_upload_size: usize,
    pub version: String,
}

pub async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<StatsResponse>, StatusCode> {
    let total = sqlx::query_scalar!("SELECT COUNT(*) FROM scans")
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or(0);

    let completed = sqlx::query_scalar!("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or(0);

    let failed = sqlx::query_scalar!("SELECT COUNT(*) FROM scans WHERE status = 'failed'")
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or(0);

    let pending = sqlx::query_scalar!("SELECT COUNT(*) FROM scans WHERE status = 'pending' OR status = 'running'")
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or(0);

    let findings = sqlx::query_scalar!("SELECT COUNT(*) FROM findings")
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or(0);

    Ok(Json(StatsResponse {
        total_scans: total,
        completed_scans: completed,
        failed_scans: failed,
        pending_scans: pending,
        total_findings: findings,
    }))
}

pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        max_upload_size: state.config.max_upload_size,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
