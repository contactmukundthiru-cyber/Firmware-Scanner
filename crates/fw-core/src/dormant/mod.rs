//! Dormant capability detection

pub mod detector;

pub use detector::detect_dormant;

use crate::analysis::CapabilityType;
use crate::evidence::Evidence;
use serde::{Deserialize, Serialize};

/// A dormant (unused but present) capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DormantCapability {
    pub id: String,
    pub capability_type: CapabilityType,
    pub name: String,
    pub description: String,
    pub activation_conditions: Vec<String>,
    pub confidence: f32,
    pub evidence: Option<Evidence>,
}

impl DormantCapability {
    pub fn new(
        id: &str,
        capability_type: CapabilityType,
        name: &str,
        description: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            capability_type,
            name: name.to_string(),
            description: description.to_string(),
            activation_conditions: Vec::new(),
            confidence: 0.5,
            evidence: None,
        }
    }

    pub fn with_conditions(mut self, conditions: Vec<String>) -> Self {
        self.activation_conditions = conditions;
        self
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence = Some(evidence);
        self
    }
}
