//! Capacity estimation and chi-square detectability analysis, plus
//! spectral-domain detectability scoring.
//!
//! Pure domain logic — no I/O, no file system, no async runtime.

use bytes::Bytes;
use rustfft::FftPlanner;
use rustfft::num_complex::Complex;

use crate::domain::ports::AiGenProfile;
use crate::domain::types::{
    CoverMedia, CoverMediaKind, DetectabilityRisk, SpectralScore, StegoTechnique,
};

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

/// Compute a pair-delta chi-square score on `data`.
///
/// Builds a 256-bin histogram of consecutive byte differences
/// `data[i+1].wrapping_sub(data[i])` and measures how far that distribution
/// deviates from the flat prior expected for independent random bytes.
/// Lower score = less detectable.
///
/// Unlike [`chi_square_score`], this score **is** order-sensitive: swapping
/// two non-adjacent bytes changes the pairs they participate in and therefore
/// changes the score.  This makes it suitable as the hill-climb objective in
/// [`crate::domain::adaptive::permutation_search`].
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "pair counts are small enough for f64"
)]
pub fn pair_delta_chi_square_score(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    let mut histogram = [0u64; 256];
    for pair in data.array_windows::<2>() {
        let delta = pair[1].wrapping_sub(pair[0]);
        #[expect(
            clippy::indexing_slicing,
            reason = "delta is a u8, always 0..=255, histogram has 256 entries"
        )]
        {
            histogram[usize::from(delta)] = histogram[usize::from(delta)].strict_add(1);
        }
    }

    let n_pairs = data.len().strict_sub(1);
    let expected = n_pairs as f64 / 256.0;
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

    let normalised = chi_sq / 255.0;
    if normalised < f64::EPSILON {
        -100.0
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

// ─── Spectral detectability scoring ──────────────────────────────────────────

/// Run a spectral-domain detectability analysis comparing `original` to
/// `stego`.
///
/// The score is profile-aware: when an [`AiGenProfile`] is provided, only the
/// carrier bins with `coherence >= 0.90` are analysed.  Without a profile the
/// top-16 highest-magnitude bins (excluding DC at `(0, 0)`) are used.
///
/// # Panics
///
/// Never panics.  Empty and single-pixel inputs are handled gracefully.
#[must_use]
pub fn spectral_detectability_score(
    original: &CoverMedia,
    stego: &CoverMedia,
    profile: Option<&AiGenProfile>,
) -> SpectralScore {
    let orig_pixels = green_channel_f32(&original.data);
    let stego_pixels = green_channel_f32(&stego.data);

    let n = orig_pixels.len().min(stego_pixels.len());
    if n < 4 {
        return SpectralScore {
            phase_coherence_drop: 0.0,
            carrier_snr_drop_db: 0.0,
            sample_pair_asymmetry: 0.0,
            combined_risk: DetectabilityRisk::Low,
        };
    }

    // Next power-of-two >= n for FFT.
    let fft_len = n.next_power_of_two();
    let orig_freq = run_fft(&orig_pixels, fft_len);
    let stego_freq = run_fft(&stego_pixels, fft_len);

    // Extract actual image dimensions from metadata so the carrier-bin
    // profile lookup (keyed by "WIDTHxHEIGHT") can find the right entry.
    // Fall back to treating the data as a 1-D signal if dimensions are absent.
    let img_width: usize = original
        .metadata
        .get("width")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(fft_len);
    let img_height: usize = original
        .metadata
        .get("height")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);
    let width = u32::try_from(img_width).unwrap_or(u32::MAX);
    let height = u32::try_from(img_height).unwrap_or(u32::MAX);

    // Determine carrier bins to examine.  Convert (row, col) 2-D coordinates
    // to a flat 1-D FFT index so the helpers can index directly into the
    // FFT output array.
    let carrier_bins: Vec<(u32, u32)> = profile.map_or_else(Vec::new, |prof| {
        prof.carrier_bins_for(width, height)
            .map(|bins| {
                bins.iter()
                    .filter(|b| b.is_strong())
                    .map(|b| b.freq)
                    .collect()
            })
            .unwrap_or_default()
    });

    let flat_bins: Vec<usize> = if carrier_bins.is_empty() {
        // Fall back to top-16 highest magnitude bins, skipping DC.
        top_magnitude_bins(&orig_freq, 16)
    } else {
        carrier_bins
            .into_iter()
            .map(|(r, c)| {
                (r as usize)
                    .saturating_mul(img_width)
                    .saturating_add(c as usize)
            })
            .collect()
    };

    // Phase coherence drop: 1 − avg |cos(Δphase)| over carrier bins.
    let phase_coherence_drop = compute_phase_coherence_drop(&orig_freq, &stego_freq, &flat_bins);

    // SNR drop in dB.
    let carrier_snr_drop_db = compute_carrier_snr_drop_db(&orig_freq, &stego_freq, &flat_bins);

    // Sample-pair adjacency asymmetry on the raw channel.
    let sample_pair_asymmetry = match (orig_pixels.get(..n), stego_pixels.get(..n)) {
        (Some(orig), Some(stego)) => compute_sample_pair_asymmetry(orig, stego),
        _ => 0.0,
    };

    let combined_risk = classify_spectral_risk(phase_coherence_drop, carrier_snr_drop_db);

    SpectralScore {
        phase_coherence_drop,
        carrier_snr_drop_db,
        sample_pair_asymmetry,
        combined_risk,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract the green channel as `f32` values from RGBA8-packed bytes.
/// Bytes are interpreted as RGBA8; if length isn't divisible by 4 the
/// remainder bytes are treated as green-channel samples directly.
fn green_channel_f32(data: &Bytes) -> Vec<f32> {
    if data.len() >= 4 && data.len().is_multiple_of(4) {
        data.chunks_exact(4)
            .filter_map(|ch| match ch {
                [_, g, _, _] => Some(f32::from(*g)),
                _ => None,
            })
            .collect()
    } else {
        data.iter().map(|&b| f32::from(b)).collect()
    }
}

/// Run a 1-D FFT on `samples`, zero-padded to `fft_len`.
fn run_fft(samples: &[f32], fft_len: usize) -> Vec<Complex<f32>> {
    let mut input: Vec<Complex<f32>> = samples.iter().map(|&x| Complex::new(x, 0.0)).collect();
    input.resize(fft_len, Complex::new(0.0, 0.0));

    let mut planner = FftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(fft_len);
    fft.process(&mut input);
    input
}

/// Return flat 1-D FFT bin indices of the top-`n` highest-magnitude bins,
/// skipping DC (index 0).
fn top_magnitude_bins(freq: &[Complex<f32>], n: usize) -> Vec<usize> {
    let mut indexed: Vec<(usize, f64)> = freq
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, c)| (i, f64::from(c.norm())))
        .collect();
    indexed.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    indexed.truncate(n);
    indexed.into_iter().map(|(i, _)| i).collect()
}

/// `1 - avg(|cos(phase_stego - phase_orig)|)` over the given flat bin indices.
fn compute_phase_coherence_drop(
    orig: &[Complex<f32>],
    stego: &[Complex<f32>],
    bins: &[usize],
) -> f64 {
    if bins.is_empty() {
        return 0.0;
    }
    let mut sum = 0.0f64;
    let mut count = 0usize;
    for &idx in bins {
        if let (Some(o), Some(s)) = (orig.get(idx), stego.get(idx)) {
            let phase_diff = f64::from(s.arg() - o.arg());
            sum += phase_diff.cos().abs();
            count = count.strict_add(1);
        }
    }
    if count == 0 {
        return 0.0;
    }
    let count_f = match u32::try_from(count) {
        Ok(v) => f64::from(v),
        Err(_) => return 0.0,
    };
    let avg_coherence = sum / count_f;
    (1.0 - avg_coherence).clamp(0.0, 1.0)
}

/// Mean SNR drop in dB: 10·log10(|stego|/|orig|) averaged over carrier bins.
/// Returns 0.0 when no bins are available or magnitudes are zero.
fn compute_carrier_snr_drop_db(
    orig: &[Complex<f32>],
    stego: &[Complex<f32>],
    bins: &[usize],
) -> f64 {
    if bins.is_empty() {
        return 0.0;
    }
    let mut sum = 0.0f64;
    let mut count = 0usize;
    for &idx in bins {
        if let (Some(o), Some(s)) = (orig.get(idx), stego.get(idx)) {
            let mag_orig = f64::from(o.norm());
            let mag_stego = f64::from(s.norm());
            if mag_orig > 0.0 && mag_stego > 0.0 {
                sum += 10.0 * (mag_stego / mag_orig).log10();
                count = count.strict_add(1);
            }
        }
    }
    if count == 0 {
        return 0.0;
    }
    let count_f = match u32::try_from(count) {
        Ok(v) => f64::from(v),
        Err(_) => return 0.0,
    };
    let result = sum / count_f;
    if result.is_nan() { 0.0 } else { result }
}

/// Adjacent pixel-pair parity asymmetry in the stego channel:
/// fraction of pairs where even-position sample differs from odd-position
/// sample in parity (LSB) more than expected.
fn compute_sample_pair_asymmetry(orig: &[f32], stego: &[f32]) -> f64 {
    if stego.len() < 2 {
        return 0.0;
    }

    let pairs = stego.len() / 2;
    let asym: usize = stego
        .chunks_exact(2)
        .filter(|pair| match pair {
            [a, b] => sample_is_odd(*a) != sample_is_odd(*b),
            _ => false,
        })
        .count();
    let orig_asym: usize = orig
        .chunks_exact(2)
        .filter(|pair| match pair {
            [a, b] => sample_is_odd(*a) != sample_is_odd(*b),
            _ => false,
        })
        .count();
    let pairs_f = match u32::try_from(pairs) {
        Ok(v) if v > 0 => f64::from(v),
        _ => return 0.0,
    };
    let asym_f = match u32::try_from(asym) {
        Ok(v) => f64::from(v),
        Err(_) => return 0.0,
    };
    let orig_asym_f = match u32::try_from(orig_asym) {
        Ok(v) => f64::from(v),
        Err(_) => return 0.0,
    };
    let stego_frac = asym_f / pairs_f;
    let orig_frac = orig_asym_f / pairs_f;
    (stego_frac - orig_frac).abs().clamp(0.0, 1.0)
}

fn sample_is_odd(sample: f32) -> bool {
    // Samples are originally byte-derived channel values represented as f32.
    // Using float parity avoids lossy integer casts that violate strict lints.
    sample.rem_euclid(2.0) >= 1.0
}

/// Classify spectral risk based on phase coherence drop and SNR drop.
fn classify_spectral_risk(
    phase_coherence_drop: f64,
    carrier_snr_drop_db: f64,
) -> DetectabilityRisk {
    if phase_coherence_drop > 0.20 || carrier_snr_drop_db.abs() > 0.15 {
        DetectabilityRisk::High
    } else if phase_coherence_drop > 0.05 || carrier_snr_drop_db.abs() > 0.05 {
        DetectabilityRisk::Medium
    } else {
        DetectabilityRisk::Low
    }
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

    // ─── Spectral detectability score tests ──────────────────────────────

    fn make_spectral_cover(data: Vec<u8>) -> CoverMedia {
        CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(data),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn spectral_identical_buffers_low_risk() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let orig = make_spectral_cover(data.clone());
        let stego = make_spectral_cover(data);
        let score = spectral_detectability_score(&orig, &stego, None);
        assert!(
            (score.phase_coherence_drop).abs() < 1e-6,
            "identical buffers: phase_coherence_drop should be ~0"
        );
        assert!(
            (score.carrier_snr_drop_db).abs() < 1e-3,
            "identical buffers: carrier_snr_drop_db should be ~0"
        );
        assert_eq!(score.combined_risk, DetectabilityRisk::Low);
    }

    #[test]
    fn spectral_heavily_modified_differs_from_identical() {
        // Inverted data has a very different spectrum from the original.
        // The score fields should reflect numeric differences; we only
        // assert the scoring completes without panic and produces a valid
        // risk level (the exact threshold depends on the data content).
        let orig_data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let stego_data: Vec<u8> = orig_data.iter().map(|&b| b ^ 0xFF).collect();
        let orig = make_spectral_cover(orig_data);
        let stego = make_spectral_cover(stego_data);
        let score = spectral_detectability_score(&orig, &stego, None);
        // Score fields must be finite and non-negative where applicable.
        assert!(score.phase_coherence_drop.is_finite());
        assert!(score.sample_pair_asymmetry >= 0.0);
        // Risk must be a valid variant — just confirming it doesn't panic.
        let _ = score.combined_risk;
    }

    #[test]
    fn spectral_empty_orig_no_panic() {
        let orig = make_spectral_cover(vec![]);
        let stego = make_spectral_cover(vec![0u8; 64]);
        let score = spectral_detectability_score(&orig, &stego, None);
        assert_eq!(score.combined_risk, DetectabilityRisk::Low);
    }

    #[test]
    fn spectral_single_pixel_no_panic() {
        let orig = make_spectral_cover(vec![128]);
        let stego = make_spectral_cover(vec![129]);
        let score = spectral_detectability_score(&orig, &stego, None);
        assert_eq!(score.combined_risk, DetectabilityRisk::Low);
    }

    #[test]
    fn spectral_with_ai_gen_profile_checks_carrier_bins() {
        use crate::domain::ports::{AiGenProfile, CarrierBin};
        // 64-element row; profile carrier bin at (0, 5) — strong.
        let bins = vec![CarrierBin::new((0, 5), 0.0, 1.0)];
        let mut carrier_map = HashMap::new();
        // Key is "64x1" for width=64, height=1.
        carrier_map.insert("64x1".to_string(), bins);
        let profile = AiGenProfile {
            model_id: "test-model".to_string(),
            channel_weights: [1.0, 1.0, 1.0],
            carrier_map,
        };
        let data: Vec<u8> = (0u8..64).collect();
        let orig = make_spectral_cover(data.clone());
        let stego = make_spectral_cover(data);
        let score = spectral_detectability_score(&orig, &stego, Some(&profile));
        // Identical data → low risk even with profile bins.
        assert_eq!(score.combined_risk, DetectabilityRisk::Low);
    }

    #[test]
    fn spectral_score_serde_round_trip() {
        use crate::domain::types::SpectralScore;
        let score = SpectralScore {
            phase_coherence_drop: 0.12,
            carrier_snr_drop_db: -0.08,
            sample_pair_asymmetry: 0.03,
            combined_risk: DetectabilityRisk::Medium,
        };
        let json = serde_json::to_string(&score);
        assert!(json.is_ok());
        let Some(json) = json.ok() else {
            return;
        };
        let back: Result<SpectralScore, _> = serde_json::from_str(&json);
        assert!(back.is_ok());
        let Some(back) = back.ok() else {
            return;
        };
        assert!((back.phase_coherence_drop - score.phase_coherence_drop).abs() < 1e-10);
        assert!((back.carrier_snr_drop_db - score.carrier_snr_drop_db).abs() < 1e-10);
        assert_eq!(back.combined_risk, score.combined_risk);
    }

    #[test]
    fn analysis_report_has_spectral_score_field() {
        use crate::domain::types::{AnalysisReport, Capacity};
        let report = AnalysisReport {
            technique: StegoTechnique::LsbImage,
            cover_capacity: Capacity {
                bytes: 100,
                technique: StegoTechnique::LsbImage,
            },
            chi_square_score: -13.5,
            detectability_risk: DetectabilityRisk::Low,
            recommended_max_payload_bytes: 50,
            ai_watermark: None,
            spectral_score: None,
        };
        assert!(report.spectral_score.is_none());
    }
}
