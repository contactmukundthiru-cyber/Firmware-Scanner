//! Report generation

pub mod json;
pub mod markdown;

use crate::ScanResult;
use crate::CoreResult;

/// Report format
pub enum ReportFormat {
    Json,
    Markdown,
    Html,
}

/// Generate report in specified format
pub fn generate_report(result: &ScanResult, format: ReportFormat) -> CoreResult<String> {
    match format {
        ReportFormat::Json => json::generate(result),
        ReportFormat::Markdown => markdown::generate(result),
        ReportFormat::Html => markdown::generate_html(result),
    }
}
