//! Evidence collection from analysis results

use super::Evidence;
use crate::analysis::AnalysisResult;
use crate::claims::ClaimVerdict;
use crate::dormant::DormantCapability;
use uuid::Uuid;

/// Evidence collector for gathering and preserving findings
pub struct EvidenceCollector {
    context_bytes: usize,
}

impl EvidenceCollector {
    pub fn new(context_bytes: usize) -> Self {
        Self { context_bytes }
    }

    /// Collect all evidence from analysis results
    pub fn collect_all(
        &self,
        raw_data: &[u8],
        analysis: &AnalysisResult,
        dormant: &[DormantCapability],
        claim_verdicts: &[ClaimVerdict],
    ) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Collect from findings
        for finding in &analysis.all_findings {
            evidence.extend(finding.evidence.clone());
        }

        // Collect from dormant capabilities
        for cap in dormant {
            if let Some(ref ev) = cap.evidence {
                evidence.push(ev.clone());
            }
        }

        // Collect from claim verdicts
        for verdict in claim_verdicts {
            evidence.extend(verdict.evidence.clone());
            for failed in &verdict.failing_conditions {
                evidence.extend(failed.evidence.clone());
            }
        }

        // Deduplicate by hash
        evidence.sort_by(|a, b| a.content_hash.cmp(&b.content_hash));
        evidence.dedup_by(|a, b| a.content_hash == b.content_hash);

        evidence
    }

    /// Create evidence from a match in data
    pub fn create_evidence(
        &self,
        finding_id: &str,
        file_path: &str,
        data: &[u8],
        offset: usize,
        length: usize,
    ) -> Evidence {
        let start = offset;
        let end = std::cmp::min(offset + length, data.len());

        let before_start = offset.saturating_sub(self.context_bytes);
        let after_end = std::cmp::min(end + self.context_bytes, data.len());

        let matched = data[start..end].to_vec();
        let before = data[before_start..start].to_vec();
        let after = data[end..after_end].to_vec();

        Evidence::new(finding_id, file_path, offset as u64, &matched, before, after)
    }

    /// Create evidence from string match
    pub fn create_string_evidence(
        &self,
        finding_id: &str,
        file_path: &str,
        data: &[u8],
        needle: &str,
    ) -> Option<Evidence> {
        let text = String::from_utf8_lossy(data);
        if let Some(pos) = text.find(needle) {
            Some(self.create_evidence(finding_id, file_path, data, pos, needle.len()))
        } else {
            None
        }
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new(64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_creation() {
        let collector = EvidenceCollector::new(32);
        let data = b"prefix_MATCH_suffix";
        let evidence = collector.create_evidence("test", "/test/file", data, 7, 5);

        assert_eq!(evidence.matched_data, b"MATCH");
        assert!(!evidence.context_before.is_empty());
        assert!(!evidence.context_after.is_empty());
    }
}
