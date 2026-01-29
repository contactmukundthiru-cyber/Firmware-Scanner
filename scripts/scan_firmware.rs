//! Firmware Scanner Automation Script
//!
//! This script downloads and scans real open source firmware samples
//! to demonstrate the system's capabilities.
//!
//! Run with: cargo run --release --example scan_firmware

use std::path::PathBuf;
use std::process::Command;

/// Sample firmware URLs for testing
const SAMPLE_FIRMWARES: &[(&str, &str)] = &[
    // OpenWRT - Open source router firmware
    ("openwrt-23.05.0-x86-64-generic-squashfs-combined.img.gz",
     "https://downloads.openwrt.org/releases/23.05.0/targets/x86/64/openwrt-23.05.0-x86-64-generic-squashfs-combined.img.gz"),

    // Tasmota - Open source IoT firmware
    ("tasmota.bin",
     "https://github.com/arendst/Tasmota/releases/download/v13.3.0/tasmota.bin"),

    // ESPHome - ESP8266/ESP32 firmware
    ("esphome-web-esp32.bin",
     "https://github.com/esphome/esphome-web/releases/download/v2024.1.0/esphome-web-esp32.factory.bin"),

    // Marlin - 3D printer firmware (sample hex file)
    ("Marlin.ino.hex",
     "https://github.com/MarlinFirmware/Configurations/raw/release-2.1.2.1/config/examples/Creality/Ender-3/README.md"),
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("===========================================");
    println!("  Firmware Scanner - Automated Test Suite  ");
    println!("===========================================\n");

    let download_dir = PathBuf::from("./test_samples");
    std::fs::create_dir_all(&download_dir)?;

    // Check for curl or wget
    let downloader = if Command::new("curl").arg("--version").output().is_ok() {
        "curl"
    } else if Command::new("wget").arg("--version").output().is_ok() {
        "wget"
    } else {
        println!("ERROR: Neither curl nor wget found. Please install one.");
        return Ok(());
    };

    println!("Using {} for downloads\n", downloader);

    for (filename, url) in SAMPLE_FIRMWARES.iter().take(2) {
        let filepath = download_dir.join(filename);

        if filepath.exists() {
            println!("[SKIP] {} already exists", filename);
        } else {
            println!("[DOWNLOAD] {}", filename);
            println!("  URL: {}", url);

            let status = if downloader == "curl" {
                Command::new("curl")
                    .args(["-L", "-o", filepath.to_str().unwrap(), url])
                    .status()?
            } else {
                Command::new("wget")
                    .args(["-O", filepath.to_str().unwrap(), url])
                    .status()?
            };

            if !status.success() {
                println!("  [WARN] Download failed, skipping");
                continue;
            }
            println!("  [OK] Downloaded successfully");
        }

        // Run the scanner
        println!("\n[SCAN] Analyzing {}", filename);
        println!("-----------------------------------------");

        let scanner_output = Command::new("cargo")
            .args(["run", "-p", "fw-cli", "--release", "--", "scan", filepath.to_str().unwrap()])
            .output();

        match scanner_output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if !stdout.is_empty() {
                    println!("{}", stdout);
                }
                if !stderr.is_empty() && !output.status.success() {
                    eprintln!("Errors: {}", stderr);
                }
            }
            Err(e) => {
                println!("  [ERROR] Failed to run scanner: {}", e);
            }
        }

        println!("-----------------------------------------\n");
    }

    println!("\n===========================================");
    println!("           Scan Complete                   ");
    println!("===========================================");

    Ok(())
}
