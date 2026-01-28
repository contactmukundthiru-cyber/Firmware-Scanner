//! Authentication routes

use crate::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in: u64,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub role: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // For demo purposes - in production use proper password hashing
    if payload.email == "admin@example.com" && payload.password == "admin" {
        let token = crate::auth::create_token(&payload.email, &state.config.jwt_secret)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(LoginResponse {
            token,
            expires_in: 3600,
        }))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn refresh(
    State(state): State<Arc<AppState>>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // Simplified - in production validate the existing token
    let token = crate::auth::create_token("admin@example.com", &state.config.jwt_secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(LoginResponse {
        token,
        expires_in: 3600,
    }))
}

pub async fn me() -> Json<UserResponse> {
    // Simplified - in production extract from JWT
    Json(UserResponse {
        id: "1".to_string(),
        email: "admin@example.com".to_string(),
        role: "admin".to_string(),
    })
}
