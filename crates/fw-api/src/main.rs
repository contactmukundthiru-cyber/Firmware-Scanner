//! Firmware Scanner API Server

mod auth;
mod db;
mod models;
mod routes;
mod workers;

use axum::{
    routing::{get, post, delete},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Application state shared across handlers
pub struct AppState {
    pub db: sqlx::PgPool,
    pub scanner: fw_core::Scanner,
    pub config: AppConfig,
}

/// Application configuration
#[derive(Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub jwt_secret: String,
    pub upload_dir: String,
    pub max_upload_size: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/firmware_scanner".to_string()),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "development-secret-change-in-production".to_string()),
            upload_dir: std::env::var("UPLOAD_DIR")
                .unwrap_or_else(|_| "./data/uploads".to_string()),
            max_upload_size: 1024 * 1024 * 1024, // 1GB
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "fw_api=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Firmware Scanner API Server");

    let config = AppConfig::default();

    // Create upload directory
    std::fs::create_dir_all(&config.upload_dir).expect("Failed to create upload directory");

    // Connect to database
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to database");

    info!("Connected to database");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("Failed to run migrations");

    info!("Database migrations complete");

    // Create scanner
    let scanner = fw_core::Scanner::new();

    // Create shared state
    let state = Arc::new(AppState {
        db,
        scanner,
        config,
    });

    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(routes::health_check))

        // Authentication
        .route("/api/auth/login", post(routes::auth::login))
        .route("/api/auth/refresh", post(routes::auth::refresh))
        .route("/api/auth/me", get(routes::auth::me))

        // Scans
        .route("/api/scans", post(routes::scans::create_scan))
        .route("/api/scans", get(routes::scans::list_scans))
        .route("/api/scans/:id", get(routes::scans::get_scan))
        .route("/api/scans/:id", delete(routes::scans::delete_scan))
        .route("/api/scans/:id/findings", get(routes::scans::get_findings))
        .route("/api/scans/:id/claims", get(routes::scans::get_claims))
        .route("/api/scans/:id/evidence", get(routes::scans::get_evidence))

        // Reports
        .route("/api/scans/:id/report", get(routes::reports::get_report))
        .route("/api/scans/:id/report/download", get(routes::reports::download_report))

        // Admin
        .route("/api/admin/stats", get(routes::admin::get_stats))
        .route("/api/admin/config", get(routes::admin::get_config))

        // CORS
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any))

        // Tracing
        .layer(TraceLayer::new_for_http())

        // State
        .with_state(state);

    // Start server
    let addr = "0.0.0.0:3000";
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
