//! Capacity estimation and chi-square detectability analysis.
//!
//! Pure domain logic — no I/O, no file system, no async runtime.

use crate::domain::types::{CoverMedia, CoverMediaKind, DetectabilityRisk, StegoTechnique};

/// `DetectabilityRisk` thresholds in dB.
const HIGH_THRESHOLD_DB: f64 = -6.0;
const MEDIUM_THRESHOLD_DB: f64 = -12.0;

/// Classify detectability risk from a chi-square score in dB.
#[must_use]
pub fn classify_risk(chi_square_db: f64) -> DetectabilityRisk {
    if chi_square_db > HIGH_THRESHOLD_DB {
        DetectabilityRisk::High
    } else if chi_square_db > MEDIUM_THRESHOLD_DB {
        DetectabilityRisk::Medium
    } else {
        DetectabilityRisk::Low
    }
}

/// Compute recommended max payload bytes for a given capacity and risk.
#[must_use]
pub const fn recommended_payload(capacity_bytes: u64, risk: DetectabilityRisk) -> u64 {
    match risk {
        DetectabilityRisk::Low => capacity_bytes / 2,
        DetectabilityRisk::Medium => capacity_bytes / 4,
        DetectabilityRisk::High => capacity_bytes / 8,
    }
}

/// Estimate embedding capacity for a cover/technique pair.
///
/// Returns capacity in bytes.
#[must_use]
pub fn estimate_capacity(cover: &CoverMedia, technique: StegoTechnique) -> u64 {
    match technique {
        StegoTechnique::LsbImage => estimate_image_lsb_capacity(cover),
        StegoTechnique::DctJpeg => estimate_jpeg_dct_capacity(cover),
        StegoTechnique::Palette => estimate_palette_capacity(cover),
        StegoTechnique::LsbAudio => estimate_audio_lsb_capacity(cover),
        StegoTechnique::PhaseEncoding | StegoTechnique::EchoHiding => {
            // Audio techniques: ~1 bit per segment
            estimate_audio_lsb_capacity(cover) / 8
        }
        StegoTechnique::ZeroWidthText => estimate_text_capacity(cover),
        StegoTechnique::PdfContentStream => estimate_pdf_content_capacity(cover),
        StegoTechnique::PdfMetadata => estimate_pdf_metadata_capacity(cover),
        StegoTechnique::CorpusSelection => {
            // Corpus reuses LsbImage capacity of the matched cover
            estimate_image_lsb_capacity(cover)
        }
        StegoTechnique::DualPayload => {
            // Dual payload splits capacity in half
            estimate_image_lsb_capacity(cover) / 2
        }
    }
}

/// Chi-square statistic on byte value distribution.
///
/// Measures how uniformly distributed the LSBs are. A perfectly random
/// distribution scores low (close to 0 dB below expected).
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "byte histogram counts are small enough for f64"
)]
pub fn chi_square_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Build byte histogram (256 bins)
    let mut histogram = [0u64; 256];
    for &b in data {
        // usize::from(u8) is always 0..=255, histogram has 256 entries
        #[expect(
            clippy::indexing_slicing,
            reason = "u8 index into [_; 256] cannot be out of bounds"
        )]
        {
            histogram[usize::from(b)] = histogram[usize::from(b)].strict_add(1);
        }
    }

    let expected = data.len() as f64 / 256.0;
    if expected < f64::EPSILON {
        return 0.0;
    }

    let chi_sq: f64 = histogram
        .iter()
        .map(|&count| {
            let diff = count as f64 - expected;
            (diff * diff) / expected
        })
        .sum();

    // Convert to dB scale relative to expected (255 degrees of freedom)
    let normalised = chi_sq / 255.0;
    if normalised < f64::EPSILON {
        -100.0 // Essentially undetectable
    } else {
        10.0 * normalised.log10()
    }
}

// ─── Private capacity estimators ──────────────────────────────────────────────

const fn estimate_image_lsb_capacity(cover: &CoverMedia) -> u64 {
    match cover.kind {
        CoverMediaKind::PngImage | CoverMediaKind::BmpImage => {
            // ~1 bit per colour channel per pixel, 3 channels
            // Rough estimate: data.len() / 8 (header overhead subtracted)
            let usable = cover.data.len().saturating_sub(54); // BMP header ~54
            (usable / 8) as u64
        }
        CoverMediaKind::GifImage => (cover.data.len().saturating_sub(128) / 16) as u64,
        _ => 0,
    }
}

fn estimate_jpeg_dct_capacity(cover: &CoverMedia) -> u64 {
    if cover.kind != CoverMediaKind::JpegImage {
        return 0;
    }
    // ~1 bit per nonzero AC coefficient; rough: data_len / 16
    (cover.data.len() / 16) as u64
}

const fn estimate_palette_capacity(cover: &CoverMedia) -> u64 {
    match cover.kind {
        CoverMediaKind::GifImage | CoverMediaKind::PngImage => {
            // ~1 bit per palette entry reorder
            (cover.data.len().saturating_sub(128) / 32) as u64
        }
        _ => 0,
    }
}

fn estimate_audio_lsb_capacity(cover: &CoverMedia) -> u64 {
    if cover.kind != CoverMediaKind::WavAudio {
        return 0;
    }
    // WAV: 1 bit per sample, 16-bit samples -> data/16 bytes
    let usable = cover.data.len().saturating_sub(44); // WAV header ~44
    (usable / 16) as u64
}

use unicode_segmentation::UnicodeSegmentation;

fn estimate_text_capacity(cover: &CoverMedia) -> u64 {
    if cover.kind != CoverMediaKind::PlainText {
        return 0;
    }
    // ~2 bits per grapheme boundary (ZWJ/ZWNJ)
    let text = String::from_utf8_lossy(&cover.data);
    let grapheme_count = text.graphemes(true).count();
    // 2 bits at each boundary = grapheme_count / 4 bytes
    (grapheme_count / 4) as u64
}

fn estimate_pdf_content_capacity(cover: &CoverMedia) -> u64 {
    if cover.kind != CoverMediaKind::PdfDocument {
        return 0;
    }
    // Rough: 1 bit per content-stream byte, ~10% of PDF is content stream
    (cover.data.len() / 80) as u64
}

const fn estimate_pdf_metadata_capacity(_cover: &CoverMedia) -> u64 {
    // Metadata fields: limited capacity (~256 bytes typical)
    256
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;

    fn make_cover(kind: CoverMediaKind, size: usize) -> CoverMedia {
        CoverMedia {
            kind,
            data: Bytes::from(vec![0u8; size]),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn classify_risk_thresholds() {
        assert_eq!(classify_risk(-1.0), DetectabilityRisk::High);
        assert_eq!(classify_risk(-5.9), DetectabilityRisk::High);
        assert_eq!(classify_risk(-7.0), DetectabilityRisk::Medium);
        assert_eq!(classify_risk(-11.9), DetectabilityRisk::Medium);
        assert_eq!(classify_risk(-13.0), DetectabilityRisk::Low);
        assert_eq!(classify_risk(-50.0), DetectabilityRisk::Low);
    }

    #[test]
    fn recommended_payload_scales_with_risk() {
        assert_eq!(recommended_payload(1000, DetectabilityRisk::Low), 500);
        assert_eq!(recommended_payload(1000, DetectabilityRisk::Medium), 250);
        assert_eq!(recommended_payload(1000, DetectabilityRisk::High), 125);
    }

    #[test]
    fn estimate_capacity_png_lsb() {
        let cover = make_cover(CoverMediaKind::PngImage, 8192);
        let cap = estimate_capacity(&cover, StegoTechnique::LsbImage);
        assert!(cap > 0);
        // (8192 - 54) / 8 = 1017
        assert_eq!(cap, 1017);
    }

    #[test]
    fn estimate_capacity_wav_lsb() {
        let cover = make_cover(CoverMediaKind::WavAudio, 44100);
        let cap = estimate_capacity(&cover, StegoTechnique::LsbAudio);
        assert!(cap > 0);
    }

    #[test]
    fn estimate_capacity_wrong_kind_returns_zero() {
        let cover = make_cover(CoverMediaKind::WavAudio, 1000);
        assert_eq!(estimate_capacity(&cover, StegoTechnique::LsbImage), 0);
    }

    #[test]
    fn chi_square_uniform_data_low_score() {
        // Uniform distribution: all byte values equally represented
        let data: Vec<u8> = (0..=255).cycle().take(256 * 100).collect();
        let score = chi_square_score(&data);
        assert!(
            score < HIGH_THRESHOLD_DB,
            "uniform data should score low: {score}"
        );
    }

    #[test]
    fn chi_square_biased_data_high_score() {
        // Heavily biased: all zeros
        let data = vec![0u8; 10000];
        let score = chi_square_score(&data);
        assert!(
            score > HIGH_THRESHOLD_DB,
            "biased data should score high: {score}"
        );
    }

    #[test]
    fn chi_square_empty_returns_zero() {
        assert!((chi_square_score(&[]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn corpus_selection_uses_image_capacity() {
        let cover = make_cover(CoverMediaKind::PngImage, 4096);
        let lsb_cap = estimate_capacity(&cover, StegoTechnique::LsbImage);
        let corpus_cap = estimate_capacity(&cover, StegoTechnique::CorpusSelection);
        assert_eq!(lsb_cap, corpus_cap);
    }

    #[test]
    fn pdf_content_stream_has_capacity() {
        let cover = make_cover(CoverMediaKind::PdfDocument, 100_000);
        let cap = estimate_capacity(&cover, StegoTechnique::PdfContentStream);
        assert!(cap > 0);
    }

    // ─── Additional capacity estimator coverage ───────────────────────────

    #[test]
    fn jpeg_dct_capacity_for_jpeg() {
        let cover = make_cover(CoverMediaKind::JpegImage, 16_000);
        let cap = estimate_capacity(&cover, StegoTechnique::DctJpeg);
        assert_eq!(cap, 1000); // 16000 / 16
    }

    #[test]
    fn jpeg_dct_capacity_wrong_kind_returns_zero() {
        let cover = make_cover(CoverMediaKind::PngImage, 16_000);
        assert_eq!(estimate_capacity(&cover, StegoTechnique::DctJpeg), 0);
    }

    #[test]
    fn palette_capacity_for_gif() {
        let cover = make_cover(CoverMediaKind::GifImage, 4096);
        let cap = estimate_capacity(&cover, StegoTechnique::Palette);
        assert!(cap > 0);
        // (4096 - 128) / 32 = 124
        assert_eq!(cap, 124);
    }

    #[test]
    fn palette_capacity_wrong_kind_returns_zero() {
        let cover = make_cover(CoverMediaKind::WavAudio, 4096);
        assert_eq!(estimate_capacity(&cover, StegoTechnique::Palette), 0);
    }

    #[test]
    fn text_capacity_for_plain_text() {
        // "hello world" has 11 grapheme clusters -> 11 / 4 = 2
        let cover = CoverMedia {
            kind: CoverMediaKind::PlainText,
            data: Bytes::from(
                "hello world, this is a test of capacity estimation for zero-width text",
            ),
            metadata: HashMap::new(),
        };
        let cap = estimate_capacity(&cover, StegoTechnique::ZeroWidthText);
        assert!(cap > 0);
    }

    #[test]
    fn text_capacity_wrong_kind_returns_zero() {
        let cover = make_cover(CoverMediaKind::PngImage, 1000);
        assert_eq!(estimate_capacity(&cover, StegoTechnique::ZeroWidthText), 0);
    }

    #[test]
    fn pdf_content_capacity_wrong_kind_returns_zero() {
        let cover = make_cover(CoverMediaKind::PngImage, 100_000);
        assert_eq!(
            estimate_capacity(&cover, StegoTechnique::PdfContentStream),
            0
        );
    }

    #[test]
    fn pdf_metadata_capacity_always_256() {
        let cover = make_cover(CoverMediaKind::PdfDocument, 1000);
        assert_eq!(estimate_capacity(&cover, StegoTechnique::PdfMetadata), 256);
        // Even for non-PDF types, metadata capacity is fixed
        let cover2 = make_cover(CoverMediaKind::PngImage, 1000);
        assert_eq!(estimate_capacity(&cover2, StegoTechnique::PdfMetadata), 256);
    }

    #[test]
    fn audio_lsb_wrong_kind_returns_zero() {
        let cover = make_cover(CoverMediaKind::PngImage, 44100);
        assert_eq!(estimate_capacity(&cover, StegoTechnique::LsbAudio), 0);
    }

    #[test]
    fn phase_encoding_is_audio_lsb_div_8() {
        let cover = make_cover(CoverMediaKind::WavAudio, 44100);
        let audio_cap = estimate_capacity(&cover, StegoTechnique::LsbAudio);
        let phase_cap = estimate_capacity(&cover, StegoTechnique::PhaseEncoding);
        assert_eq!(phase_cap, audio_cap / 8);
    }

    #[test]
    fn echo_hiding_same_as_phase_encoding() {
        let cover = make_cover(CoverMediaKind::WavAudio, 44100);
        let phase_cap = estimate_capacity(&cover, StegoTechnique::PhaseEncoding);
        let echo_cap = estimate_capacity(&cover, StegoTechnique::EchoHiding);
        assert_eq!(phase_cap, echo_cap);
    }

    #[test]
    fn dual_payload_is_half_image_lsb() {
        let cover = make_cover(CoverMediaKind::PngImage, 8192);
        let lsb_cap = estimate_capacity(&cover, StegoTechnique::LsbImage);
        let dual_cap = estimate_capacity(&cover, StegoTechnique::DualPayload);
        assert_eq!(dual_cap, lsb_cap / 2);
    }

    #[test]
    fn gif_lsb_image_capacity() {
        let cover = make_cover(CoverMediaKind::GifImage, 4096);
        let cap = estimate_capacity(&cover, StegoTechnique::LsbImage);
        // (4096 - 128) / 16 = 248
        assert_eq!(cap, 248);
    }

    #[test]
    fn bmp_lsb_same_as_png() {
        let cover_png = make_cover(CoverMediaKind::PngImage, 8192);
        let cover_bmp = make_cover(CoverMediaKind::BmpImage, 8192);
        assert_eq!(
            estimate_capacity(&cover_png, StegoTechnique::LsbImage),
            estimate_capacity(&cover_bmp, StegoTechnique::LsbImage)
        );
    }

    #[test]
    fn palette_capacity_for_png() {
        let cover = make_cover(CoverMediaKind::PngImage, 4096);
        let cap = estimate_capacity(&cover, StegoTechnique::Palette);
        assert_eq!(cap, 124); // Same formula as GIF
    }
}
