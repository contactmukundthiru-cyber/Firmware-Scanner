//! Firmware Scanner CLI

use clap::{Parser, Subcommand};
use fw_core::{Scanner, ScanConfig, claims::Claim, report::{self, ReportFormat}};
use std::path::PathBuf;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "fw-scan")]
#[command(about = "Firmware Telemetry & Capability Analysis Tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a firmware image
    Scan {
        /// Path to firmware file
        #[arg(short, long)]
        file: PathBuf,

        /// Output format (json, markdown, html)
        #[arg(short, long, default_value = "markdown")]
        output: String,

        /// Output file (defaults to stdout)
        #[arg(short = 'O', long)]
        output_file: Option<PathBuf>,

        /// Claims to verify (comma-separated)
        #[arg(short, long)]
        claims: Option<String>,

        /// Disable dormant capability detection
        #[arg(long)]
        no_dormant: bool,

        /// Maximum recursion depth for nested containers
        #[arg(long, default_value = "10")]
        max_depth: usize,
    },

    /// Verify specific claims against firmware
    Verify {
        /// Path to firmware file
        #[arg(short, long)]
        file: PathBuf,

        /// Claims to verify (comma-separated: offline,no-telemetry,no-tracking,no-remote)
        #[arg(short, long)]
        claims: String,
    },

    /// Extract information about a firmware image
    Info {
        /// Path to firmware file
        #[arg(short, long)]
        file: PathBuf,
    },

    /// List supported formats
    Formats,
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    match cli.command {
        Commands::Scan { file, output, output_file, claims, no_dormant, max_depth } => {
            cmd_scan(file, output, output_file, claims, no_dormant, max_depth);
        }
        Commands::Verify { file, claims } => {
            cmd_verify(file, claims);
        }
        Commands::Info { file } => {
            cmd_info(file);
        }
        Commands::Formats => {
            cmd_formats();
        }
    }
}

fn cmd_scan(
    file: PathBuf,
    output_format: String,
    output_file: Option<PathBuf>,
    claims: Option<String>,
    no_dormant: bool,
    max_depth: usize,
) {
    info!("Scanning firmware: {}", file.display());

    if !file.exists() {
        error!("File not found: {}", file.display());
        std::process::exit(1);
    }

    // Parse claims
    let claims_to_verify = parse_claims(claims);

    // Configure scanner
    let config = ScanConfig {
        max_recursion_depth: max_depth,
        detect_dormant: !no_dormant,
        claims_to_verify,
        ..Default::default()
    };

    let scanner = Scanner::with_config(config);

    // Run scan
    match scanner.scan_file(&file) {
        Ok(result) => {
            info!("Scan completed: {} findings", result.summary.total_capabilities_found);

            // Generate report
            let format = match output_format.to_lowercase().as_str() {
                "json" => ReportFormat::Json,
                "html" => ReportFormat::Html,
                _ => ReportFormat::Markdown,
            };

            match report::generate_report(&result, format) {
                Ok(report_content) => {
                    if let Some(out_path) = output_file {
                        std::fs::write(&out_path, &report_content)
                            .expect("Failed to write output file");
                        info!("Report written to: {}", out_path.display());
                    } else {
                        println!("{}", report_content);
                    }
                }
                Err(e) => {
                    error!("Failed to generate report: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            error!("Scan failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_verify(file: PathBuf, claims_str: String) {
    info!("Verifying claims for: {}", file.display());

    if !file.exists() {
        error!("File not found: {}", file.display());
        std::process::exit(1);
    }

    let claims = parse_claims(Some(claims_str));

    let config = ScanConfig {
        claims_to_verify: claims.clone(),
        ..Default::default()
    };

    let scanner = Scanner::with_config(config);

    match scanner.scan_file(&file) {
        Ok(result) => {
            println!("\nClaim Verification Results\n{}", "=".repeat(50));

            let mut all_passed = true;

            for verdict in &result.claim_verdicts {
                let status = match verdict.compatible {
                    fw_core::TriState::Yes => "PASS",
                    fw_core::TriState::No => {
                        all_passed = false;
                        "FAIL"
                    },
                    fw_core::TriState::Indeterminate => "UNKNOWN",
                };

                println!("\n{}: {}", verdict.claim.name(), status);
                println!("  {}", verdict.explanation);

                if !verdict.failing_conditions.is_empty() {
                    println!("  Failing conditions:");
                    for failed in &verdict.failing_conditions {
                        println!("    - {}: {}", failed.condition_type, failed.description);
                    }
                }
            }

            println!("\n{}", "=".repeat(50));
            if all_passed {
                println!("All claims VERIFIED");
            } else {
                println!("Some claims FAILED verification");
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Verification failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_info(file: PathBuf) {
    info!("Extracting info from: {}", file.display());

    if !file.exists() {
        error!("File not found: {}", file.display());
        std::process::exit(1);
    }

    let data = std::fs::read(&file).expect("Failed to read file");

    println!("\nFirmware Information\n{}", "=".repeat(50));
    println!("File: {}", file.display());
    println!("Size: {} bytes ({:.2} MB)", data.len(), data.len() as f64 / 1024.0 / 1024.0);

    // Hash
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hex::encode(hasher.finalize());
    println!("SHA-256: {}", hash);

    // Entropy
    let entropy = fw_parsers::magic::calculate_entropy(&data);
    println!("Entropy: {:.4} bits/byte", entropy);
    if entropy > 7.9 {
        println!("  WARNING: High entropy suggests encryption/compression");
    }

    // Format detection
    if let Some(format) = fw_parsers::magic::detect_file_type(&data) {
        println!("Format: {}", format);
    } else {
        println!("Format: Unknown");
    }

    // Nested signatures
    let signatures = fw_parsers::magic::detect_all_formats(&data, 65536);
    if signatures.len() > 1 {
        println!("\nNested Containers:");
        for (offset, _format, desc) in &signatures {
            println!("  0x{:08x}: {}", offset, desc);
        }
    }
}

fn cmd_formats() {
    println!("\nSupported Formats\n{}", "=".repeat(50));

    println!("\nArchives:");
    println!("  - gzip (.gz)");
    println!("  - bzip2 (.bz2)");
    println!("  - xz (.xz)");
    println!("  - lz4 (.lz4)");
    println!("  - zstd (.zst)");
    println!("  - tar (.tar)");
    println!("  - zip (.zip)");
    println!("  - cpio");

    println!("\nFilesystems:");
    println!("  - SquashFS");
    println!("  - CramFS");
    println!("  - ext2/ext3/ext4");
    println!("  - JFFS2");
    println!("  - YAFFS/YAFFS2");
    println!("  - UBI/UBIFS");
    println!("  - RomFS");

    println!("\nExecutables:");
    println!("  - ELF (32/64-bit, LE/BE)");
    println!("  - PE (32/64-bit)");

    println!("\nFirmware Containers:");
    println!("  - Android boot image");
    println!("  - Android sparse image");
    println!("  - U-Boot legacy image");
    println!("  - U-Boot FIT image");
}

fn parse_claims(claims_str: Option<String>) -> Vec<Claim> {
    let mut claims = Vec::new();

    if let Some(s) = claims_str {
        for claim in s.split(',') {
            match claim.trim().to_lowercase().as_str() {
                "offline" => claims.push(Claim::Offline),
                "no-telemetry" | "notelemetry" => claims.push(Claim::NoTelemetry),
                "no-tracking" | "notracking" => claims.push(Claim::NoTracking),
                "air-gapped" | "airgapped" => claims.push(Claim::AirGapped),
                "local-only" | "localonly" => claims.push(Claim::LocalOnly),
                "no-remote" | "noremote" | "no-remote-access" => claims.push(Claim::NoRemoteAccess),
                "no-update" | "noupdate" | "no-auto-update" => claims.push(Claim::NoAutoUpdate),
                "ephemeral" | "ephemeral-data" => claims.push(Claim::EphemeralData),
                _ => {
                    eprintln!("Warning: Unknown claim '{}', ignoring", claim);
                }
            }
        }
    }

    if claims.is_empty() {
        // Default claims
        claims = vec![
            Claim::Offline,
            Claim::NoTelemetry,
            Claim::NoTracking,
            Claim::NoRemoteAccess,
        ];
    }

    claims
}
