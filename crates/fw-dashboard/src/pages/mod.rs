//! Dashboard pages

mod dashboard;
mod scans;
mod reports;
mod settings;

pub use dashboard::Dashboard;
pub use scans::{ScansPage, ScanDetail};
pub use reports::ReportsPage;
pub use settings::SettingsPage;
