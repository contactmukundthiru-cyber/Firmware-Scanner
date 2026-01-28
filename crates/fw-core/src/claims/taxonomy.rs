//! Claim taxonomy and definitions

use crate::analysis::CapabilityType;
use serde::{Deserialize, Serialize};

/// Vendor claims that can be verified
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Claim {
    /// Device operates fully offline
    Offline,
    /// No telemetry or data collection
    NoTelemetry,
    /// No user tracking or correlation
    NoTracking,
    /// Air-gapped, no network connectivity
    AirGapped,
    /// All processing is local
    LocalOnly,
    /// User has full control over data
    UserControlledData,
    /// No remote access capability
    NoRemoteAccess,
    /// No automatic updates
    NoAutoUpdate,
    /// Data is not persistent
    EphemeralData,
    /// Custom claim
    Custom(String),
}

impl Claim {
    pub fn name(&self) -> &str {
        match self {
            Claim::Offline => "Offline",
            Claim::NoTelemetry => "No Telemetry",
            Claim::NoTracking => "No Tracking",
            Claim::AirGapped => "Air-Gapped",
            Claim::LocalOnly => "Local Only",
            Claim::UserControlledData => "User-Controlled Data",
            Claim::NoRemoteAccess => "No Remote Access",
            Claim::NoAutoUpdate => "No Auto Update",
            Claim::EphemeralData => "Ephemeral Data",
            Claim::Custom(s) => s,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Claim::Offline => "Device operates without network connectivity",
            Claim::NoTelemetry => "Device does not collect or transmit telemetry data",
            Claim::NoTracking => "Device does not track or correlate user activity",
            Claim::AirGapped => "Device has no network interfaces or connectivity",
            Claim::LocalOnly => "All data processing occurs on-device",
            Claim::UserControlledData => "User has complete control over their data",
            Claim::NoRemoteAccess => "Device cannot be accessed or controlled remotely",
            Claim::NoAutoUpdate => "Device does not automatically update firmware",
            Claim::EphemeralData => "Device does not persist user data",
            Claim::Custom(_) => "Custom claim",
        }
    }

    /// Get the requirements for this claim
    pub fn requirements(&self) -> ClaimRequirement {
        match self {
            Claim::Offline => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![CapabilityType::Networking],
                required_present: vec![],
                conditions: vec![
                    Condition::NoNetworkStack,
                    Condition::NoUrls,
                    Condition::NoIpAddresses,
                ],
            },
            Claim::NoTelemetry => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![CapabilityType::Telemetry],
                required_present: vec![],
                conditions: vec![
                    Condition::NoAnalyticsEndpoints,
                    Condition::NoCrashReporting,
                    Condition::NoMetricsCollection,
                ],
            },
            Claim::NoTracking => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![CapabilityType::Identity],
                required_present: vec![],
                conditions: vec![
                    Condition::NoDeviceFingerprinting,
                    Condition::NoAdvertisingIds,
                    Condition::NoPersistentIdentifiers,
                ],
            },
            Claim::AirGapped => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![CapabilityType::Networking],
                required_present: vec![],
                conditions: vec![
                    Condition::NoNetworkStack,
                    Condition::NoNetworkDrivers,
                    Condition::NoWirelessSupport,
                ],
            },
            Claim::LocalOnly => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![CapabilityType::Networking, CapabilityType::Telemetry],
                required_present: vec![],
                conditions: vec![
                    Condition::NoUrls,
                    Condition::NoRemoteEndpoints,
                ],
            },
            Claim::UserControlledData => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![CapabilityType::Telemetry],
                required_present: vec![],
                conditions: vec![
                    Condition::NoAutoUpload,
                    Condition::NoBackdoorAccess,
                ],
            },
            Claim::NoRemoteAccess => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![CapabilityType::Update],
                required_present: vec![],
                conditions: vec![
                    Condition::NoRemoteShell,
                    Condition::NoRemoteCommand,
                    Condition::NoBackdoorAccess,
                ],
            },
            Claim::NoAutoUpdate => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![],
                required_present: vec![],
                conditions: vec![
                    Condition::NoOtaUpdate,
                    Condition::NoAutoFirmwareUpdate,
                ],
            },
            Claim::EphemeralData => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![CapabilityType::Storage],
                required_present: vec![],
                conditions: vec![
                    Condition::NoDatabase,
                    Condition::NoPersistentStorage,
                ],
            },
            Claim::Custom(_) => ClaimRequirement {
                claim: self.clone(),
                required_absent: vec![],
                required_present: vec![],
                conditions: vec![],
            },
        }
    }
}

/// Requirements for a claim to be satisfied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequirement {
    pub claim: Claim,
    pub required_absent: Vec<CapabilityType>,
    pub required_present: Vec<CapabilityType>,
    pub conditions: Vec<Condition>,
}

/// Specific conditions for claim verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    // Networking
    NoNetworkStack,
    NoUrls,
    NoIpAddresses,
    NoNetworkDrivers,
    NoWirelessSupport,
    NoRemoteEndpoints,

    // Telemetry
    NoAnalyticsEndpoints,
    NoCrashReporting,
    NoMetricsCollection,
    NoAutoUpload,

    // Identity
    NoDeviceFingerprinting,
    NoAdvertisingIds,
    NoPersistentIdentifiers,

    // Update/Remote
    NoOtaUpdate,
    NoAutoFirmwareUpdate,
    NoRemoteShell,
    NoRemoteCommand,
    NoBackdoorAccess,

    // Storage
    NoDatabase,
    NoPersistentStorage,
}

impl Condition {
    pub fn description(&self) -> &str {
        match self {
            Condition::NoNetworkStack => "No TCP/IP or network stack present",
            Condition::NoUrls => "No embedded URLs",
            Condition::NoIpAddresses => "No hardcoded IP addresses",
            Condition::NoNetworkDrivers => "No network interface drivers",
            Condition::NoWirelessSupport => "No WiFi/Bluetooth/Cellular support",
            Condition::NoRemoteEndpoints => "No remote server endpoints",
            Condition::NoAnalyticsEndpoints => "No analytics service connections",
            Condition::NoCrashReporting => "No crash reporting services",
            Condition::NoMetricsCollection => "No metrics collection code",
            Condition::NoAutoUpload => "No automatic data upload",
            Condition::NoDeviceFingerprinting => "No device fingerprinting",
            Condition::NoAdvertisingIds => "No advertising identifiers",
            Condition::NoPersistentIdentifiers => "No persistent device identifiers",
            Condition::NoOtaUpdate => "No OTA update mechanism",
            Condition::NoAutoFirmwareUpdate => "No automatic firmware updates",
            Condition::NoRemoteShell => "No remote shell access",
            Condition::NoRemoteCommand => "No remote command execution",
            Condition::NoBackdoorAccess => "No backdoor access methods",
            Condition::NoDatabase => "No database storage",
            Condition::NoPersistentStorage => "No persistent data storage",
        }
    }
}
