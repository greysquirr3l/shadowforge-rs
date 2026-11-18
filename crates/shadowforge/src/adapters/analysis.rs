//! Adapter implementing the [`CapacityAnalyser`] port.

use crate::domain::analysis::{
    chi_square_score, classify_risk, estimate_capacity, recommended_payload,
};
use crate::domain::errors::AdaptiveError;
use crate::domain::errors::AnalysisError;
use crate::domain::ports::CapacityAnalyser;
use crate::domain::types::{AnalysisReport, Capacity, CoverMedia, CoverMediaKind, StegoTechnique};

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

/// The capacity of `cover` for `technique`.
///
/// PDF content-stream capacity is measured rather than estimated: it
/// depends on the numeric operands in the document's page content streams,
/// and a figure derived from the file size overstates it by orders of
/// magnitude. The PDF adapter counts those operands, so it is asked
/// directly.
fn capacity_for(cover: &CoverMedia, technique: StegoTechnique) -> u64 {
    #[cfg(feature = "pdf")]
    if technique == StegoTechnique::PdfContentStream {
        // Measured from the document itself. If the document cannot be
        // parsed, fall back to the figure the PDF adapter recorded when it
        // loaded the file.
        return crate::adapters::pdf::pdf_content_stream_capacity(cover).map_or_else(
            |_| {
                cover
                    .metadata
                    .get(crate::domain::analysis::PDF_CONTENT_STREAM_CAPACITY_KEY)
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0)
            },
            |capacity| capacity.bytes,
        );
    }

    estimate_capacity(cover, technique)
}

impl CapacityAnalyser for CapacityAnalyserImpl {
    fn analyse(
        &self,
        cover: &CoverMedia,
        technique: StegoTechnique,
    ) -> Result<AnalysisReport, AnalysisError> {
        let cap_bytes = capacity_for(cover, technique);
        if cap_bytes == 0 {
            // A PDF whose content streams are too small to hold even the
            // length prefix is compatible with the technique, just too
            // small to use it — saying otherwise sends the reader looking
            // for the wrong problem.
            let reason = if technique == StegoTechnique::PdfContentStream
                && cover.kind == CoverMediaKind::PdfDocument
            {
                "the document's content streams are too small to hold a payload".to_string()
            } else {
                format!("{:?} is not compatible with {:?}", cover.kind, technique)
            };
            return Err(AnalysisError::UnsupportedCoverType { reason });
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

    /// The analysis must report the capacity the technique can actually
    /// use.
    ///
    /// A figure derived from the document's size overstates the real
    /// capacity by orders of magnitude, so the analyser measures the
    /// document's content streams instead.
    #[cfg(feature = "pdf")]
    #[test]
    fn analyse_pdf_content_stream() -> TestResult {
        use crate::domain::ports::EmbedTechnique;

        let analyser = CapacityAnalyserImpl::new();
        let cover = pdf_cover_with_operands(80);
        let report = analyser.analyse(&cover, StegoTechnique::PdfContentStream)?;
        assert!(
            report.cover_capacity.bytes > 0,
            "a content stream with operands must report capacity"
        );

        // The analysis and the technique must agree.
        let technique_capacity = crate::adapters::pdf::PdfContentStreamStego::new()
            .capacity(&cover)?
            .bytes;
        assert_eq!(
            report.cover_capacity.bytes, technique_capacity,
            "the analysis and the technique must report the same capacity"
        );
        Ok(())
    }

    /// A PDF cover whose page content stream holds `operands` numbers.
    #[cfg(feature = "pdf")]
    fn pdf_cover_with_operands(operands: usize) -> CoverMedia {
        use lopdf::dictionary;
        use lopdf::{Document, Object};

        use std::fmt::Write as _;

        let mut content = String::from("S\n");
        for i in 0..operands {
            let _ = write!(content, "{i} {} m ", i * 2);
        }

        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let leaf_id = doc.new_object_id();
        let content_id = doc.add_object(lopdf::Stream::new(
            lopdf::dictionary! {},
            content.into_bytes(),
        ));
        doc.objects.insert(
            leaf_id,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference(content_id),
            }),
        );
        doc.objects.insert(
            pages_id,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(leaf_id)],
                "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(pages_id),
        });
        doc.trailer.set("Root", Object::Reference(catalog_id));

        let mut bytes = Vec::new();
        doc.save_to(&mut std::io::BufWriter::new(&mut bytes))
            .unwrap_or_default();

        CoverMedia {
            kind: CoverMediaKind::PdfDocument,
            data: bytes.into(),
            metadata: HashMap::new(),
        }
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
