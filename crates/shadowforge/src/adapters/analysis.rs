//! Adapter implementing the [`CapacityAnalyser`] port.

use crate::domain::analysis::{
    chi_square_score, classify_risk, estimate_capacity, recommended_payload,
};
use crate::domain::errors::AnalysisError;
use crate::domain::ports::CapacityAnalyser;
use crate::domain::types::{AnalysisReport, Capacity, CoverMedia, StegoTechnique};

/// Concrete [`CapacityAnalyser`] implementation.
pub struct CapacityAnalyserImpl;

impl Default for CapacityAnalyserImpl {
    fn default() -> Self {
        Self
    }
}

impl CapacityAnalyserImpl {
    /// Create a new analyser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CapacityAnalyser for CapacityAnalyserImpl {
    fn analyse(
        &self,
        cover: &CoverMedia,
        technique: StegoTechnique,
    ) -> Result<AnalysisReport, AnalysisError> {
        let cap_bytes = estimate_capacity(cover, technique);
        if cap_bytes == 0 {
            return Err(AnalysisError::UnsupportedCoverType {
                reason: format!("{:?} is not compatible with {:?}", cover.kind, technique),
            });
        }

        let chi_sq = chi_square_score(&cover.data);
        let risk = classify_risk(chi_sq);
        let recommended = recommended_payload(cap_bytes, risk);

        Ok(AnalysisReport {
            technique,
            cover_capacity: Capacity {
                bytes: cap_bytes,
                technique,
            },
            chi_square_score: chi_sq,
            detectability_risk: risk,
            recommended_max_payload_bytes: recommended,
            spectral_score: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{CoverMediaKind, DetectabilityRisk};
    use bytes::Bytes;
    use std::collections::HashMap;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn make_cover(kind: CoverMediaKind, data: Vec<u8>) -> CoverMedia {
        CoverMedia {
            kind,
            data: Bytes::from(data),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn analyse_png_lsb_low_risk_for_uniform() -> TestResult {
        let analyser = CapacityAnalyserImpl::new();
        // Uniform-ish data for low chi-square
        let data: Vec<u8> = (0..=255).cycle().take(256 * 40).collect();
        let cover = make_cover(CoverMediaKind::PngImage, data);
        let report = analyser.analyse(&cover, StegoTechnique::LsbImage)?;

        assert!(report.cover_capacity.bytes > 0);
        assert_eq!(report.detectability_risk, DetectabilityRisk::Low);
        assert!(report.recommended_max_payload_bytes > 0);
        Ok(())
    }

    #[test]
    fn analyse_returns_error_for_incompatible_type() {
        let analyser = CapacityAnalyserImpl::new();
        let cover = make_cover(CoverMediaKind::WavAudio, vec![0u8; 1000]);
        let result = analyser.analyse(&cover, StegoTechnique::LsbImage);
        assert!(result.is_err());
    }

    #[test]
    fn analyse_pdf_content_stream() -> TestResult {
        let analyser = CapacityAnalyserImpl::new();
        let cover = make_cover(CoverMediaKind::PdfDocument, vec![0u8; 50_000]);
        let report = analyser.analyse(&cover, StegoTechnique::PdfContentStream)?;
        assert!(report.cover_capacity.bytes > 0);
        Ok(())
    }

    #[test]
    fn analyse_corpus_selection_low_risk() -> TestResult {
        let analyser = CapacityAnalyserImpl::new();
        let data: Vec<u8> = (0..=255).cycle().take(256 * 32).collect();
        let cover = make_cover(CoverMediaKind::PngImage, data);
        let report = analyser.analyse(&cover, StegoTechnique::CorpusSelection)?;
        // Corpus selection should always be low risk if the cover data is uniform
        assert_eq!(report.detectability_risk, DetectabilityRisk::Low);
        Ok(())
    }

    #[test]
    fn report_serialises_to_json() -> TestResult {
        let analyser = CapacityAnalyserImpl::new();
        let data: Vec<u8> = (0..=255).cycle().take(8192).collect();
        let cover = make_cover(CoverMediaKind::PngImage, data);
        let report = analyser.analyse(&cover, StegoTechnique::LsbImage)?;
        let json = serde_json::to_string(&report)?;
        assert!(json.contains("\"technique\""));
        assert!(json.contains("\"chi_square_score\""));
        Ok(())
    }
}
