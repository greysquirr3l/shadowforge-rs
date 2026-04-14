//! Adaptive embedding adapters: cover-profile matching, STC-inspired
//! optimisation, and platform compression simulation.
//!
//! I/O is allowed here; domain logic lives in `domain/adaptive`.

use std::io::Cursor;
use std::sync::LazyLock;

use bytes::Bytes;
use rustfft::FftPlanner;
use rustfft::num_complex::Complex;
use serde::Deserialize;

use crate::domain::adaptive::{BinMask, SearchConfig, permutation_search};
use crate::domain::errors::AdaptiveError;
use crate::domain::ports::{
    AdaptiveOptimiser, AiGenProfile, CameraProfile, CarrierBin, CompressionSimulator, CoverProfile,
    CoverProfileMatcher,
};
use crate::domain::types::{
    AiWatermarkAssessment, Capacity, CoverMedia, CoverMediaKind, PlatformProfile, StegoTechnique,
};

// ─── Built-in AI codebook ────────────────────────────────────────────────────

/// Deserialisation wrapper for `ai_profiles.json`.
#[derive(Deserialize)]
struct ProfileCodebook {
    profiles: Vec<AiGenProfile>,
}

// ─── CoverProfileMatcherImpl ─────────────────────────────────────────────────

/// Concrete cover-profile matcher.
///
/// Loaded from a JSON codebook at construction time.  The built-in codebook
/// includes the Gemini watermark profile.
pub struct CoverProfileMatcherImpl {
    ai_profiles: Vec<AiGenProfile>,
    camera_profiles: Vec<CameraProfile>,
}

struct AiProfileMatch<'a> {
    profile: &'a AiGenProfile,
    matched_strong_bins: usize,
    total_strong_bins: usize,
    /// 1.0 for exact resolution + native scale; stacked penalty otherwise.
    confidence_multiplier: f64,
    /// Mean `|cos(obs_phase − expected_phase)|` over matched strong G-channel bins.
    phase_consistency: f64,
    /// Weighted fraction of matched bins where R and B channels also agree.
    cross_validation_score: f64,
}

impl CoverProfileMatcherImpl {
    /// Parse an AI profile codebook from a JSON string.
    ///
    /// # Errors
    /// Returns [`AdaptiveError::ProfileMatchFailed`] if the JSON is malformed.
    pub fn from_codebook(json: &str) -> Result<Self, AdaptiveError> {
        let book: ProfileCodebook =
            serde_json::from_str(json).map_err(|e| AdaptiveError::ProfileMatchFailed {
                reason: format!("invalid codebook JSON: {e}"),
            })?;
        Ok(Self {
            ai_profiles: book.profiles,
            camera_profiles: Vec::new(),
        })
    }

    /// Build using the built-in `ai_profiles.json` codebook bundled at
    /// compile time.
    ///
    /// # Panics
    ///
    /// Never panics in production — the embedded JSON is validated at
    /// compile-time test level.
    #[must_use]
    pub fn with_built_in() -> Self {
        static BUILT_IN: LazyLock<Vec<AiGenProfile>> = LazyLock::new(|| {
            let raw = include_str!("ai_profiles.json");
            match serde_json::from_str::<ProfileCodebook>(raw) {
                Ok(book) => book.profiles,
                Err(e) => {
                    tracing::error!(
                        "built-in AI profile codebook is malformed — \
                         adaptive matching is disabled: {e}"
                    );
                    Vec::new()
                }
            }
        });
        Self {
            ai_profiles: BUILT_IN.clone(),
            camera_profiles: Vec::new(),
        }
    }

    const fn ai_detection_supported(kind: CoverMediaKind) -> bool {
        matches!(
            kind,
            CoverMediaKind::PngImage
                | CoverMediaKind::BmpImage
                | CoverMediaKind::JpegImage
                | CoverMediaKind::GifImage
        )
    }

    fn detection_threshold(total_strong_bins: usize) -> usize {
        total_strong_bins.saturating_sub(1).max(1)
    }

    #[expect(
        clippy::similar_names,
        reason = "R/G/B channel triples are intentionally symmetric; names like fft_r_half/fft_b_half reflect the domain"
    )]
    fn best_ai_profile_match(&self, cover: &CoverMedia) -> Option<AiProfileMatch<'_>> {
        let width = cover
            .metadata
            .get("width")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let height = cover
            .metadata
            .get("height")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        if width == 0 || height == 0 {
            return None;
        }

        // Build multi-channel image pyramid (native → ½ → ¼).
        // G is the primary carrier; R and B are used for cross-validation.
        let pixels_g_nat = extract_channel_f32(&cover.data, width, height, 1);
        if pixels_g_nat.len() < 4 {
            return None;
        }
        let pixels_r_nat = extract_channel_f32(&cover.data, width, height, 0);
        let pixels_b_nat = extract_channel_f32(&cover.data, width, height, 2);

        let w = width as usize;
        let h = height as usize;
        let hw = width.saturating_div(2) as usize;
        let hh = height.saturating_div(2) as usize;
        let pixels_g_half = downsample_2x(&pixels_g_nat, w, h);
        let pixels_r_half = downsample_2x(&pixels_r_nat, w, h);
        let pixels_b_half = downsample_2x(&pixels_b_nat, w, h);
        let pixels_g_qtr = downsample_2x(&pixels_g_half, hw, hh);
        let pixels_r_qtr = downsample_2x(&pixels_r_half, hw, hh);
        let pixels_b_qtr = downsample_2x(&pixels_b_half, hw, hh);

        let fft_g_nat = fft_1d(&pixels_g_nat, pixels_g_nat.len().next_power_of_two());
        let fft_r_nat = compute_fft_or_empty(&pixels_r_nat);
        let fft_b_nat = compute_fft_or_empty(&pixels_b_nat);
        let fft_g_half = compute_fft_or_empty(&pixels_g_half);
        let fft_r_half = compute_fft_or_empty(&pixels_r_half);
        let fft_b_half = compute_fft_or_empty(&pixels_b_half);
        let fft_g_qtr = compute_fft_or_empty(&pixels_g_qtr);
        let fft_r_qtr = compute_fft_or_empty(&pixels_r_qtr);
        let fft_b_qtr = compute_fft_or_empty(&pixels_b_qtr);

        self.ai_profiles
            .iter()
            .filter_map(|profile| {
                // Exact resolution match first; fall back to nearest if absent.
                let (bins, confidence_multiplier) =
                    if let Some(exact) = profile.carrier_bins_for(width, height) {
                        (exact, 1.0_f64)
                    } else {
                        nearest_resolution_bins(profile, width, height)?
                    };

                let total_strong_bins = bins.iter().filter(|b| b.is_strong()).count();
                if total_strong_bins == 0 {
                    return None;
                }

                // Run phase-coherence at native, ½, and ¼ scales; take the best.
                let half_w = width.saturating_div(2);
                let quarter_w = width.saturating_div(4);
                let (best_detail, scale_penalty) = [
                    Some((&fft_g_nat, &fft_r_nat, &fft_b_nat, width, 0u32, 1.0_f64)),
                    if fft_g_half.is_empty() {
                        None
                    } else {
                        Some((&fft_g_half, &fft_r_half, &fft_b_half, half_w, 1, 0.85))
                    },
                    if fft_g_qtr.is_empty() {
                        None
                    } else {
                        Some((&fft_g_qtr, &fft_r_qtr, &fft_b_qtr, quarter_w, 2, 0.75))
                    },
                ]
                .into_iter()
                .flatten()
                .map(|(fg, fr, fb, sw, shift, penalty)| {
                    let detail = phase_match_detail_at_scale(
                        fg, fr, fb, sw, bins, shift, profile.channel_weights,
                    );
                    (detail, penalty)
                })
                .max_by_key(|(detail, _)| detail.matched_strong)?;

                Some(AiProfileMatch {
                    profile,
                    matched_strong_bins: best_detail.matched_strong,
                    total_strong_bins: best_detail.total_strong,
                    confidence_multiplier: confidence_multiplier * scale_penalty,
                    phase_consistency: best_detail.phase_consistency,
                    cross_validation_score: best_detail.cross_validation,
                })
            })
            .max_by_key(|candidate| candidate.matched_strong_bins)
    }

    /// Assess whether a raster cover still matches a known AI watermark profile.
    #[must_use]
    pub fn assess_ai_watermark(&self, cover: &CoverMedia) -> Option<AiWatermarkAssessment> {
        if !Self::ai_detection_supported(cover.kind) {
            return None;
        }

        let Some(best_match) = self.best_ai_profile_match(cover) else {
            return Some(AiWatermarkAssessment {
                detected: false,
                model_id: None,
                confidence: 0.0,
                matched_strong_bins: 0,
                total_strong_bins: 0,
            });
        };

        let confidence = best_match.phase_consistency
            * best_match.cross_validation_score
            * best_match.confidence_multiplier;
        let detected = best_match.matched_strong_bins
            >= Self::detection_threshold(best_match.total_strong_bins);

        Some(AiWatermarkAssessment {
            detected,
            model_id: detected.then(|| best_match.profile.model_id.clone()),
            confidence,
            matched_strong_bins: best_match.matched_strong_bins,
            total_strong_bins: best_match.total_strong_bins,
        })
    }
}

impl CoverProfileMatcher for CoverProfileMatcherImpl {
    fn profile_for(&self, cover: &CoverMedia) -> Option<CoverProfile> {
        if let Some(best_match) = self.best_ai_profile_match(cover)
            && best_match.matched_strong_bins
                >= Self::detection_threshold(best_match.total_strong_bins)
        {
            return Some(CoverProfile::AiGenerator(best_match.profile.clone()));
        }

        // Fallback: camera profile if any are loaded.
        self.camera_profiles
            .first()
            .cloned()
            .map(CoverProfile::Camera)
    }

    fn apply_profile(
        &self,
        cover: CoverMedia,
        _profile: &CoverProfile,
    ) -> Result<CoverMedia, AdaptiveError> {
        // For AI profiles: no modification — the optimiser avoids carrier bins.
        // For camera profiles: a real implementation would adjust quant tables
        // via the JPEG encoder; stub returns cover unchanged.
        Ok(cover)
    }
}

// ─── AdaptiveOptimiserImpl ───────────────────────────────────────────────────

/// Concrete adversarial optimiser.
///
/// Uses `permutation_search` from `domain/adaptive` to find a byte-reordering
/// that minimises chi-square detectability.
pub struct AdaptiveOptimiserImpl {
    matcher: CoverProfileMatcherImpl,
    config: SearchConfig,
}

impl AdaptiveOptimiserImpl {
    /// Create with an explicit codebook and search configuration.
    ///
    /// # Errors
    /// Returns [`AdaptiveError::ProfileMatchFailed`] if the codebook is invalid.
    pub fn from_codebook(codebook_json: &str, config: SearchConfig) -> Result<Self, AdaptiveError> {
        Ok(Self {
            matcher: CoverProfileMatcherImpl::from_codebook(codebook_json)?,
            config,
        })
    }

    /// Create with the built-in Gemini codebook and default search config.
    #[must_use]
    pub fn with_built_in() -> Self {
        Self {
            matcher: CoverProfileMatcherImpl::with_built_in(),
            config: SearchConfig::default(),
        }
    }
}

impl AdaptiveOptimiser for AdaptiveOptimiserImpl {
    fn optimise(
        &self,
        mut stego: CoverMedia,
        _original: &CoverMedia,
        target_db: f64,
    ) -> Result<CoverMedia, AdaptiveError> {
        let width = stego
            .metadata
            .get("width")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1);
        let height = stego
            .metadata
            .get("height")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1);

        let profile = self.matcher.profile_for(&stego);
        let fallback_profile = CoverProfile::Camera(CameraProfile {
            quantisation_table: [0u16; 64],
            noise_floor_db: -80.0,
            model_id: "fallback".to_string(),
        });
        let mask = BinMask::build(profile.as_ref().unwrap_or(&fallback_profile), width, height);

        let config = SearchConfig {
            max_iterations: self.config.max_iterations,
            target_db,
        };

        // Derive deterministic seed from first 8 bytes of the stego data.
        let seed = stego.data.get(..8).map_or_else(
            || 0,
            |bytes| {
                let mut seed_bytes = [0u8; 8];
                seed_bytes.copy_from_slice(bytes);
                u64::from_le_bytes(seed_bytes)
            },
        );

        let mut data = stego.data.to_vec();
        let perm = permutation_search(&data, &mask, &config, seed);
        perm.apply(&mut data);
        stego.data = Bytes::from(data);
        Ok(stego)
    }
}

// ─── CompressionSimulatorImpl ────────────────────────────────────────────────

/// Platform-specific quality and chroma settings.
#[derive(Debug, Clone, Copy)]
struct PlatformSettings {
    jpeg_quality: u8,
}

impl PlatformSettings {
    const fn for_platform(platform: &PlatformProfile) -> Self {
        match platform {
            PlatformProfile::Instagram => Self { jpeg_quality: 82 },
            PlatformProfile::Twitter => Self { jpeg_quality: 75 },
            PlatformProfile::WhatsApp | PlatformProfile::Imgur => Self { jpeg_quality: 85 },
            PlatformProfile::Telegram => Self { jpeg_quality: 95 },
            PlatformProfile::Custom { quality, .. } => Self {
                jpeg_quality: *quality,
            },
        }
    }
}

/// Compression simulator using the `image` crate for in-memory JPEG encode/
/// decode.  No temporary files are used — bytes flow through a `Cursor`.
pub struct CompressionSimulatorImpl;

impl CompressionSimulator for CompressionSimulatorImpl {
    fn simulate(
        &self,
        cover: CoverMedia,
        platform: &PlatformProfile,
    ) -> Result<CoverMedia, AdaptiveError> {
        let settings = PlatformSettings::for_platform(platform);
        let quality = settings.jpeg_quality;

        let width = cover
            .metadata
            .get("width")
            .and_then(|v| v.parse::<u32>().ok());
        let height = cover
            .metadata
            .get("height")
            .and_then(|v| v.parse::<u32>().ok());

        // We can only JPEG-compress actual image data.  If we lack dimensions
        // or the cover isn't an image type, return unchanged.
        let (Some(w), Some(h)) = (width, height) else {
            return Ok(cover);
        };

        if !matches!(
            cover.kind,
            CoverMediaKind::PngImage
                | CoverMediaKind::JpegImage
                | CoverMediaKind::BmpImage
                | CoverMediaKind::GifImage
        ) {
            return Ok(cover);
        }

        // Treat raw data as RGBA8 pixels.
        let pixels = cover.data.to_vec();
        let expected_len = (w as usize).saturating_mul(h as usize).saturating_mul(3);
        if pixels.len() < expected_len {
            return Ok(cover);
        }

        // Encode as JPEG into memory.
        let mut encoded: Vec<u8> = Vec::new();
        {
            let mut cursor = Cursor::new(&mut encoded);
            let mut jpeg_encoder =
                image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, quality);
            image::ImageBuffer::<image::Rgb<u8>, _>::from_raw(
                w,
                h,
                pixels.get(..expected_len).unwrap_or(&[]),
            )
            .ok_or_else(|| AdaptiveError::CompressionSimFailed {
                reason: "invalid pixel dimensions".to_string(),
            })
            .and_then(|buf| {
                jpeg_encoder
                    .encode(buf.as_raw(), w, h, image::ExtendedColorType::Rgb8)
                    .map_err(|e| AdaptiveError::CompressionSimFailed {
                        reason: format!("JPEG encode failed: {e}"),
                    })
            })?;
        }

        // Decode back.
        let decoded = image::load_from_memory_with_format(&encoded, image::ImageFormat::Jpeg)
            .map_err(|e| AdaptiveError::CompressionSimFailed {
                reason: format!("JPEG decode failed: {e}"),
            })?;
        let rgb = decoded.to_rgb8();
        let mut out_meta = cover.metadata;
        out_meta.insert("width".to_string(), w.to_string());
        out_meta.insert("height".to_string(), h.to_string());

        Ok(CoverMedia {
            kind: CoverMediaKind::JpegImage,
            data: Bytes::from(rgb.into_raw()),
            metadata: out_meta,
        })
    }

    fn survivable_capacity(
        &self,
        cover: &CoverMedia,
        platform: &PlatformProfile,
    ) -> Result<Capacity, AdaptiveError> {
        let total_bytes = cover.data.len() as u64;
        let basis_points: u64 = match platform {
            PlatformProfile::Instagram | PlatformProfile::Custom { .. } => 4000,
            PlatformProfile::Twitter => 3000,
            PlatformProfile::WhatsApp | PlatformProfile::Imgur => 4500,
            PlatformProfile::Telegram => 7000,
        };
        let survivable = total_bytes.saturating_mul(basis_points).div_euclid(10_000);
        Ok(Capacity {
            bytes: survivable,
            technique: StegoTechnique::LsbImage,
        })
    }
}

// ─── Dependency factory ───────────────────────────────────────────────────────

/// Construct the three built-in adaptive adapters that together form the
/// default profile-hardening dependency set.
///
/// Call sites should keep the returned values alive for as long as an
/// [`crate::application::services::AdaptiveProfileDeps`] that borrows them
/// is in scope.
///
/// Placing this factory in the adapter layer keeps the interface layer free
/// from knowing *which* concrete types implement the adaptive port traits.
#[must_use]
pub fn build_adaptive_profile_deps() -> (
    CoverProfileMatcherImpl,
    AdaptiveOptimiserImpl,
    CompressionSimulatorImpl,
) {
    (
        CoverProfileMatcherImpl::with_built_in(),
        AdaptiveOptimiserImpl::with_built_in(),
        CompressionSimulatorImpl,
    )
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract a single colour channel from flat RGBA8 or RGB8 pixel data.
///
/// `channel` is a 0-based index: 0=R, 1=G, 2=B (3=A for RGBA8).
/// Falls back to treating each byte as a grey value when the buffer layout
/// cannot be determined.
fn extract_channel_f32(data: &Bytes, width: u32, height: u32, channel: usize) -> Vec<f32> {
    let npix = (width as usize).saturating_mul(height as usize);
    if data.len() >= npix.saturating_mul(4) {
        // RGBA8
        data.chunks_exact(4)
            .map(|ch| f32::from(ch.get(channel).copied().unwrap_or(0)))
            .collect()
    } else if data.len() >= npix.saturating_mul(3) {
        // RGB8 — clamp channel index to 0..=2
        let idx = channel.min(2);
        data.chunks_exact(3)
            .map(|ch| f32::from(ch.get(idx).copied().unwrap_or(0)))
            .collect()
    } else {
        data.iter().map(|&b| f32::from(b)).collect()
    }
}

/// Compute the 1-D FFT of `pixels`, zero-padded to the next power of two.
/// Returns an empty `Vec` when `pixels` is empty.
fn compute_fft_or_empty(pixels: &[f32]) -> Vec<Complex<f32>> {
    if pixels.is_empty() {
        Vec::new()
    } else {
        fft_1d(pixels, pixels.len().next_power_of_two())
    }
}

fn fft_1d(samples: &[f32], fft_len: usize) -> Vec<Complex<f32>> {
    let mut input: Vec<Complex<f32>> = samples.iter().map(|&x| Complex::new(x, 0.0)).collect();
    input.resize(fft_len, Complex::new(0.0, 0.0));
    let mut planner = FftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(fft_len);
    fft.process(&mut input);
    input
}

/// Parse a `"WxH"` resolution key into `(width, height)`.
fn parse_resolution_key(key: &str) -> Option<(u32, u32)> {
    let (w, h) = key.split_once('x')?;
    Some((w.parse().ok()?, h.parse().ok()?))
}

/// Confidence multiplier applied when the exact resolution is absent from the
/// codebook and the detector falls back to the nearest available resolution.
const FALLBACK_CONFIDENCE_MULTIPLIER: f64 = 0.65;

/// Return the bin slice from `profile` whose resolution is closest to
/// `(width, height)` by pixel count and aspect ratio, together with
/// [`FALLBACK_CONFIDENCE_MULTIPLIER`] to signal the approximation.
///
/// Proximity score: `|actual_pixels − candidate_pixels| / actual_pixels + |Δ AR|`.
///
/// Returns `None` only when the profile has no carrier bins at all.
fn nearest_resolution_bins(
    profile: &AiGenProfile,
    width: u32,
    height: u32,
) -> Option<(&[CarrierBin], f64)> {
    let actual_pixels = u64::from(width).saturating_mul(u64::from(height));
    let actual_ar = f64::from(width) / f64::from(height.max(1));

    profile
        .carrier_map
        .iter()
        .filter_map(|(key, bins)| {
            let (cw, ch) = parse_resolution_key(key)?;
            let candidate_pixels = u64::from(cw).saturating_mul(u64::from(ch));
            #[expect(
                clippy::cast_precision_loss,
                reason = "pixel counts fit in f64 mantissa for realistic image dimensions"
            )]
            let pixel_diff = {
                let diff = actual_pixels.abs_diff(candidate_pixels) as f64;
                let denom = actual_pixels.max(1) as f64;
                diff / denom
            };
            let ar_diff = (actual_ar - f64::from(cw) / f64::from(ch.max(1))).abs();
            Some((pixel_diff + ar_diff, bins.as_slice()))
        })
        .min_by(|(score_a, _), (score_b, _)| {
            score_a
                .partial_cmp(score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(_, bins)| (bins, FALLBACK_CONFIDENCE_MULTIPLIER))
}

/// Box-filter downsample by ×½ on a flat single-channel `f32` buffer.
///
/// Each output sample is the mean of the corresponding 2×2 input block.
/// Returns an empty `Vec` when `width < 2`, `height < 2`, or the buffer is
/// shorter than `width × height`.
fn downsample_2x(pixels: &[f32], width: usize, height: usize) -> Vec<f32> {
    let out_w = width / 2;
    let out_h = height / 2;
    if out_w == 0 || out_h == 0 || pixels.len() < width.saturating_mul(height) {
        return Vec::new();
    }
    (0..out_h)
        .flat_map(move |oy| {
            (0..out_w).map(move |ox| {
                let r0 = oy.saturating_mul(2).saturating_mul(width);
                let r1 = oy.saturating_mul(2).saturating_add(1).saturating_mul(width);
                let tl = pixels.get(r0 + ox * 2).copied().unwrap_or(0.0);
                let tr = pixels.get(r0 + ox * 2 + 1).copied().unwrap_or(0.0);
                let bl = pixels.get(r1 + ox * 2).copied().unwrap_or(0.0);
                let br = pixels.get(r1 + ox * 2 + 1).copied().unwrap_or(0.0);
                (tl + tr + bl + br) / 4.0
            })
        })
        .collect()
}

/// Detailed result of a phase-coherence check at one pyramid scale.
struct ScaleMatchDetail {
    matched_strong: usize,
    total_strong: usize,
    /// Mean `|cos(obs_phase − expected_phase)|` over matched strong G-channel bins.
    phase_consistency: f64,
    /// Weighted fraction of matched bins where R and B also show coherence.
    cross_validation: f64,
}

/// Full phase-coherence measurement for `bins` at one pyramid scale.
///
/// G channel is the primary carrier; R and B are cross-validated using
/// `channel_weights[0]` (R) and `channel_weights[2]` (B) from the profile's `channel_weights`.
/// `scale_shift` = `log₂(native_width / scaled_width)`: 0 = native, 1 = ½, 2 = ¼.
fn phase_match_detail_at_scale(
    freq_g: &[Complex<f32>],
    freq_r: &[Complex<f32>],
    freq_b: &[Complex<f32>],
    scaled_width: u32,
    bins: &[CarrierBin],
    scale_shift: u32,
    channel_weights: [f64; 3],
) -> ScaleMatchDetail {
    let r_weight = channel_weights.first().copied().unwrap_or(0.0);
    let b_weight = channel_weights.get(2).copied().unwrap_or(0.0);
    let divisor = 1u32.wrapping_shl(scale_shift);
    let total_strong = bins.iter().filter(|b| b.is_strong()).count();
    let mut matched_strong = 0usize;
    let mut phase_cos_sum = 0.0_f64;
    let mut r_cross = 0usize;
    let mut b_cross = 0usize;

    for bin in bins.iter().filter(|b| b.is_strong()) {
        let row = bin.freq.0.saturating_div(divisor);
        let col = bin.freq.1.saturating_div(divisor);
        let idx = (row as usize).saturating_mul(scaled_width as usize) + col as usize;

        let Some(carrier_g) = freq_g.get(idx) else {
            continue;
        };
        let phase_diff = f64::from(carrier_g.arg()) - bin.phase;
        if phase_diff.abs() >= std::f64::consts::PI / 8.0 {
            continue;
        }
        matched_strong += 1;
        phase_cos_sum += phase_diff.cos().abs();
        if freq_r
            .get(idx)
            .is_some_and(|c| (f64::from(c.arg()) - bin.phase).abs() < std::f64::consts::PI / 8.0)
        {
            r_cross += 1;
        }
        if freq_b
            .get(idx)
            .is_some_and(|c| (f64::from(c.arg()) - bin.phase).abs() < std::f64::consts::PI / 8.0)
        {
            b_cross += 1;
        }
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "bin counts are small; f64 precision loss is negligible"
    )]
    let phase_consistency = if matched_strong == 0 {
        0.0
    } else {
        phase_cos_sum / matched_strong as f64
    };

    let weight_sum = r_weight + b_weight;
    #[expect(
        clippy::cast_precision_loss,
        reason = "bin counts are small; f64 precision loss is negligible"
    )]
    let cross_validation = if weight_sum < 1e-10 || matched_strong == 0 {
        1.0 // No channel-weight data; do not penalise.
    } else {
        let ms = matched_strong as f64;
        r_weight.mul_add(r_cross as f64 / ms, b_weight * (b_cross as f64 / ms)) / weight_sum
    };

    ScaleMatchDetail {
        matched_strong,
        total_strong,
        phase_consistency,
        cross_validation,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_cover(kind: CoverMediaKind, w: u32, h: u32) -> CoverMedia {
        let n = (w as usize).saturating_mul(h as usize).saturating_mul(4);
        let mut meta = HashMap::new();
        meta.insert("width".to_string(), w.to_string());
        meta.insert("height".to_string(), h.to_string());
        CoverMedia {
            kind,
            data: Bytes::from(vec![128u8; n]),
            metadata: meta,
        }
    }

    #[test]
    fn built_in_codebook_parses_without_error() {
        let matcher = CoverProfileMatcherImpl::with_built_in();
        assert!(!matcher.ai_profiles.is_empty());
        let first = matcher.ai_profiles.first();
        assert!(first.is_some());
        assert_eq!(first.map(|p| p.model_id.as_str()), Some("gemini"));
    }

    #[test]
    fn from_codebook_returns_error_on_bad_json() {
        let result = CoverProfileMatcherImpl::from_codebook("not json");
        assert!(result.is_err());
    }

    #[test]
    fn from_codebook_accepts_valid_json() {
        let json = r#"{"profiles":[{"model_id":"test","channel_weights":[1.0,1.0,1.0],"carrier_map":{}}]}"#;
        let result = CoverProfileMatcherImpl::from_codebook(json);
        assert!(result.is_ok());
    }

    #[test]
    fn profile_for_returns_none_for_zero_dimensions() {
        let matcher = CoverProfileMatcherImpl::with_built_in();
        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(vec![0u8; 16]),
            metadata: HashMap::new(), // no width/height
        };
        assert!(matcher.profile_for(&cover).is_none());
    }

    #[test]
    fn assess_ai_watermark_detects_matching_profile() -> Result<(), Box<dyn std::error::Error>> {
        let matcher = CoverProfileMatcherImpl::from_codebook(
            r#"{"profiles":[{"model_id":"test-ai","channel_weights":[1.0,1.0,1.0],"carrier_map":{"8x8":[{"freq":[0,0],"phase":0.0,"coherence":1.0}]}}]}"#,
        )?;
        let cover = make_cover(CoverMediaKind::PngImage, 8, 8);

        let assessment = matcher.assess_ai_watermark(&cover);
        assert!(
            assessment.is_some(),
            "expected ai watermark assessment for matching cover"
        );
        let Some(assessment) = assessment else {
            return Ok(());
        };
        assert!(assessment.detected);
        assert_eq!(assessment.model_id.as_deref(), Some("test-ai"));
        assert_eq!(assessment.matched_strong_bins, 1);
        assert_eq!(assessment.total_strong_bins, 1);
        Ok(())
    }

    #[test]
    fn phase_match_detail_perfect_phase_gives_consistency_one() {
        // Uniform input → DC component has arg ≈ 0; bin expects 0.0.
        // Both phase_consistency and cross_validation must be ≈ 1.0.
        let samples: Vec<f32> = vec![100.0; 64];
        let fft_len = samples.len().next_power_of_two();
        let freq = fft_1d(&samples, fft_len);
        let bins = vec![CarrierBin::new((0, 0), 0.0, 1.0)];
        let detail = phase_match_detail_at_scale(&freq, &freq, &freq, 8, &bins, 0, [1.0, 1.0, 1.0]);
        assert_eq!(detail.matched_strong, 1);
        assert!(
            (detail.phase_consistency - 1.0).abs() < 1e-5,
            "expected phase_consistency ≈ 1.0, got {}",
            detail.phase_consistency
        );
        assert!(
            (detail.cross_validation - 1.0).abs() < 1e-5,
            "expected cross_validation ≈ 1.0, got {}",
            detail.cross_validation
        );
    }

    #[test]
    fn confidence_is_in_unit_interval() -> Result<(), Box<dyn std::error::Error>> {
        let matcher = CoverProfileMatcherImpl::from_codebook(
            r#"{"profiles":[{"model_id":"test-ai","channel_weights":[1.0,1.0,1.0],"carrier_map":{"8x8":[{"freq":[0,0],"phase":0.0,"coherence":1.0}]}}]}"#,
        )?;
        let cover = make_cover(CoverMediaKind::PngImage, 8, 8);
        let assessment = matcher.assess_ai_watermark(&cover);
        assert!(
            assessment.is_some(),
            "expected assessment for matching cover"
        );
        let Some(assessment) = assessment else {
            return Ok(());
        };
        assert!(
            (0.0..=1.0).contains(&assessment.confidence),
            "confidence must be in [0.0, 1.0], got {}",
            assessment.confidence
        );
        Ok(())
    }

    #[test]
    fn downsample_2x_produces_box_filtered_output() {
        // 4×4 single-channel input; expect 2×2 box-filtered output.
        let input = vec![
            1.0_f32, 2.0, 3.0, 4.0, // row 0
            5.0, 6.0, 7.0, 8.0, // row 1
            9.0, 10.0, 11.0, 12.0, // row 2
            13.0, 14.0, 15.0, 16.0, // row 3
        ];
        let output = downsample_2x(&input, 4, 4);
        assert_eq!(output.len(), 4, "expected 2×2 output");
        // Top-left block (rows 0-1, cols 0-1): (1+2+5+6)/4 = 3.5
        let tl = output.first().copied().unwrap_or(0.0);
        assert!((tl - 3.5).abs() < 1e-5, "top-left expected 3.5, got {tl}");
        // Top-right block (rows 0-1, cols 2-3): (3+4+7+8)/4 = 5.5
        let tr = output.get(1).copied().unwrap_or(0.0);
        assert!((tr - 5.5).abs() < 1e-5, "top-right expected 5.5, got {tr}");
    }

    #[test]
    fn resolution_fallback_uses_nearest_profile() -> Result<(), Box<dyn std::error::Error>> {
        // Profile registers only "16x16"; querying at 8×8 must still produce a
        // result via the nearest-resolution fallback (with reduced confidence).
        let matcher = CoverProfileMatcherImpl::from_codebook(
            r#"{"profiles":[{"model_id":"fallback-test","channel_weights":[1.0,1.0,1.0],"carrier_map":{"16x16":[{"freq":[0,0],"phase":0.0,"coherence":1.0}]}}]}"#,
        )?;
        let cover = make_cover(CoverMediaKind::PngImage, 8, 8);

        let assessment = matcher.assess_ai_watermark(&cover);
        assert!(
            assessment.is_some(),
            "expected Some from fallback resolution match"
        );
        let Some(assessment) = assessment else {
            return Ok(());
        };
        // Fallback multiplier (0.65) means confidence < 1.0 even for a perfect bin match.
        assert!(
            assessment.confidence < 1.0,
            "fallback should reduce confidence below 1.0, got {}",
            assessment.confidence
        );
        assert_eq!(assessment.total_strong_bins, 1);
        Ok(())
    }

    #[test]
    fn apply_profile_returns_cover_unchanged() {
        let matcher = CoverProfileMatcherImpl::with_built_in();
        let cover = make_cover(CoverMediaKind::PngImage, 8, 8);
        let profile = CoverProfile::Camera(CameraProfile {
            quantisation_table: [0u16; 64],
            noise_floor_db: -80.0,
            model_id: "test".to_string(),
        });
        let result = matcher.apply_profile(cover.clone(), &profile);
        assert!(result.is_ok());
        let Some(result) = result.ok() else {
            return;
        };
        assert_eq!(result.data, cover.data);
    }

    #[test]
    fn adaptive_optimiser_built_in_runs_without_error() {
        let optimiser = AdaptiveOptimiserImpl::with_built_in();
        let cover = make_cover(CoverMediaKind::PngImage, 8, 8);
        let stego = make_cover(CoverMediaKind::PngImage, 8, 8);
        let result = optimiser.optimise(stego, &cover, -12.0);
        assert!(result.is_ok());
    }

    #[test]
    fn adaptive_optimiser_preserves_data_length() {
        let optimiser = AdaptiveOptimiserImpl::with_built_in();
        let cover = make_cover(CoverMediaKind::PngImage, 4, 4);
        let stego = make_cover(CoverMediaKind::PngImage, 4, 4);
        let original_len = stego.data.len();
        let result = optimiser.optimise(stego, &cover, -12.0);
        assert!(result.is_ok());
        let Some(result) = result.ok() else {
            return;
        };
        assert_eq!(result.data.len(), original_len);
    }

    #[test]
    fn compression_simulator_survivable_capacity() {
        let sim = CompressionSimulatorImpl;
        let cover = make_cover(CoverMediaKind::PngImage, 32, 32);
        let cap = sim.survivable_capacity(&cover, &PlatformProfile::Instagram);
        assert!(cap.is_ok());
        let Some(cap) = cap.ok() else {
            return;
        };
        assert!(cap.bytes > 0);
        assert!(cap.bytes < cover.data.len() as u64);
    }

    #[test]
    fn compression_simulator_non_image_returns_unchanged() {
        let sim = CompressionSimulatorImpl;
        let cover = CoverMedia {
            kind: CoverMediaKind::WavAudio,
            data: Bytes::from(vec![0u8; 1024]),
            metadata: {
                let mut m = HashMap::new();
                m.insert("width".to_string(), "32".to_string());
                m.insert("height".to_string(), "32".to_string());
                m
            },
        };
        let result = sim.simulate(cover.clone(), &PlatformProfile::Twitter);
        assert!(result.is_ok());
        let Some(result) = result.ok() else {
            return;
        };
        assert_eq!(result.data, cover.data);
    }

    #[test]
    fn platform_settings_telegram_highest_quality() {
        let t = PlatformSettings::for_platform(&PlatformProfile::Telegram);
        let i = PlatformSettings::for_platform(&PlatformProfile::Twitter);
        assert!(t.jpeg_quality > i.jpeg_quality);

        let sim = CompressionSimulatorImpl;
        let cover = make_cover(CoverMediaKind::PngImage, 32, 32);
        let t_cap = sim.survivable_capacity(&cover, &PlatformProfile::Telegram);
        let i_cap = sim.survivable_capacity(&cover, &PlatformProfile::Twitter);
        assert!(t_cap.is_ok());
        assert!(i_cap.is_ok());
        let Some(t_cap) = t_cap.ok() else {
            return;
        };
        let Some(i_cap) = i_cap.ok() else {
            return;
        };
        assert!(t_cap.bytes > i_cap.bytes);
    }

    #[test]
    fn build_adaptive_profile_deps_returns_functional_impls() {
        let (matcher, _optimiser, _compressor) = build_adaptive_profile_deps();
        // The matcher must have loaded the built-in codebook.
        assert!(!matcher.ai_profiles.is_empty());
    }
}
