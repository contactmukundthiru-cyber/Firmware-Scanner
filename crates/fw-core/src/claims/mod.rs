//! Claim compatibility verification engine

pub mod engine;
pub mod taxonomy;

pub use engine::ClaimEngine;
pub use taxonomy::{Claim, ClaimRequirement, Condition};

use crate::analysis::{AnalysisResult, CapabilityType};
use crate::evidence::Evidence;
use crate::ingestion::FirmwareArtifact;
use crate::TriState;
use serde::{Deserialize, Serialize};

/// Claim verification verdict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimVerdict {
    pub claim: Claim,
    pub compatible: TriState,
    pub failing_conditions: Vec<FailedCondition>,
    pub evidence: Vec<Evidence>,
    pub explanation: String,
}

impl ClaimVerdict {
    pub fn is_compatible(&self) -> bool {
        self.compatible == TriState::Yes
    }

    pub fn is_incompatible(&self) -> bool {
        self.compatible == TriState::No
    }

    pub fn is_indeterminate(&self) -> bool {
        self.compatible == TriState::Indeterminate
    }
}

/// A condition that failed during claim verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedCondition {
    pub condition_type: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
}
