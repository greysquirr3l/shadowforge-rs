//! Adapter implementing the [`CapacityAnalyser`] port.

use crate::domain::analysis::{
    chi_square_score, classify_risk, estimate_capacity, recommended_payload,
};
use crate::domain::errors::AdaptiveError;
use crate::domain::errors::AnalysisError;
use crate::domain::ports::CapacityAnalyser;
use crate::domain::types::{AnalysisReport, Capacity, CoverMedia, StegoTechnique};

/// Concrete [`CapacityAnalyser`] implementation.
///
/// This type is `#[non_exhaustive]`; always construct it via [`Self::new`] or
/// [`Self::from_codebook`] rather than struct-literal syntax.
#[non_exhaustive]
pub struct CapacityAnalyserImpl {
    matcher: crate::adapters::adaptive::CoverProfileMatcherImpl,
}

impl Default for CapacityAnalyserImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl CapacityAnalyserImpl {
    /// Create a new analyser.
    #[must_use]
    pub fn new() -> Self {
        Self {
            matcher: crate::adapters::adaptive::CoverProfileMatcherImpl::with_built_in(),
        }
    }

    /// Create an analyser with an explicit AI profile codebook.
    ///
    /// # Errors
    /// Returns [`AdaptiveError::ProfileMatchFailed`] if the codebook is invalid.
    pub fn from_codebook(codebook_json: &str) -> Result<Self, AdaptiveError> {
        Ok(Self {
            matcher: crate::adapters::adaptive::CoverProfileMatcherImpl::from_codebook(
                codebook_json,
            )?,
        })
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
            ai_watermark: self.matcher.assess_ai_watermark(cover),
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

    fn make_image_cover(
        kind: CoverMediaKind,
        width: u32,
        height: u32,
        data: Vec<u8>,
    ) -> CoverMedia {
        let mut metadata = HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());
        CoverMedia {
            kind,
            data: Bytes::from(data),
            metadata,
        }
    }

    #[test]
    fn analyse_png_lsb_low_risk_for_uniform() -> TestResult {
        let analyser = CapacityAnalyserImpl::new();
        // Uniform-ish data for low chi-square
        let data: Vec<u8> = (0..=255).cycle().take(256 * 40).collect();
        let cover = make_image_cover(CoverMediaKind::PngImage, 64, 40, data);
        let report = analyser.analyse(&cover, StegoTechnique::LsbImage)?;

        assert!(report.cover_capacity.bytes > 0);
        assert_eq!(report.detectability_risk, DetectabilityRisk::Low);
        assert!(report.recommended_max_payload_bytes > 0);
        assert!(report.ai_watermark.is_some());
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
        let cover = make_image_cover(CoverMediaKind::PngImage, 64, 32, data);
        let report = analyser.analyse(&cover, StegoTechnique::CorpusSelection)?;
        // Corpus selection should always be low risk if the cover data is uniform
        assert_eq!(report.detectability_risk, DetectabilityRisk::Low);
        Ok(())
    }

    #[test]
    fn analyse_reports_ai_watermark_match_for_matching_cover() -> TestResult {
        let analyser = CapacityAnalyserImpl::from_codebook(
            r#"{"profiles":[{"model_id":"test-ai","channel_weights":[1.0,1.0,1.0],"carrier_map":{"8x8":[{"freq":[0,0],"phase":0.0,"coherence":1.0}]}}]}"#,
        )?;
        let cover = make_image_cover(CoverMediaKind::PngImage, 8, 8, vec![128u8; 8 * 8 * 4]);

        let report = analyser.analyse(&cover, StegoTechnique::LsbImage)?;
        assert!(
            report.ai_watermark.is_some(),
            "image analysis should include ai watermark assessment"
        );
        let Some(ai_watermark) = report.ai_watermark else {
            return Ok(());
        };
        assert!(ai_watermark.detected);
        assert_eq!(ai_watermark.model_id.as_deref(), Some("test-ai"));
        assert_eq!(ai_watermark.matched_strong_bins, 1);
        assert_eq!(ai_watermark.total_strong_bins, 1);
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
