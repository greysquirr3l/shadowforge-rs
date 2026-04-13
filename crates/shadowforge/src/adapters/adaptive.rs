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
    AdaptiveOptimiser, AiGenProfile, CameraProfile, CompressionSimulator, CoverProfile,
    CoverProfileMatcher,
};
use crate::domain::types::{
    AiWatermarkAssessment, Capacity, CoverMedia, CoverMediaKind, PlatformProfile,
    StegoTechnique,
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

        let pixels = extract_green_f32(&cover.data, width, height);
        if pixels.len() < 4 {
            return None;
        }

        let fft_len = pixels.len().next_power_of_two();
        let freq = fft_1d(&pixels, fft_len);

        self.ai_profiles
            .iter()
            .filter_map(|profile| {
                let bins = profile.carrier_bins_for(width, height)?;
                let total_strong_bins = bins.iter().filter(|b| b.is_strong()).count();
                if total_strong_bins == 0 {
                    return None;
                }

                let matched_strong_bins = bins
                    .iter()
                    .filter(|b| b.is_strong())
                    .filter(|b| {
                        let idx = b.freq.0 as usize * width as usize + b.freq.1 as usize;
                        freq.get(idx).is_some_and(|carrier| {
                            (f64::from(carrier.arg()) - b.phase).abs() < std::f64::consts::PI / 8.0
                        })
                    })
                    .count();

                Some(AiProfileMatch {
                    profile,
                    matched_strong_bins,
                    total_strong_bins,
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

        #[expect(
            clippy::cast_precision_loss,
            reason = "small testable bin counts converted for a user-facing ratio"
        )]
        let confidence = best_match.matched_strong_bins as f64 / best_match.total_strong_bins as f64;
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

fn extract_green_f32(data: &Bytes, width: u32, height: u32) -> Vec<f32> {
    let expected = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(4);
    if data.len() >= expected {
        // RGBA8
        data.chunks_exact(4)
            .filter_map(|ch| match ch {
                [_, g, _, _] => Some(f32::from(*g)),
                _ => None,
            })
            .collect()
    } else if data.len()
        >= (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(3)
    {
        // RGB8
        data.chunks_exact(3)
            .filter_map(|ch| match ch {
                [_, g, _] => Some(f32::from(*g)),
                _ => None,
            })
            .collect()
    } else {
        data.iter().map(|&b| f32::from(b)).collect()
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
    fn assess_ai_watermark_detects_matching_profile() {
        let matcher = CoverProfileMatcherImpl::from_codebook(
            r#"{"profiles":[{"model_id":"test-ai","channel_weights":[1.0,1.0,1.0],"carrier_map":{"8x8":[{"freq":[0,0],"phase":0.0,"coherence":1.0}]}}]}"#,
        )
        .unwrap_or_else(|_| panic!("valid JSON codebook should parse"));
        let cover = make_cover(CoverMediaKind::PngImage, 8, 8);

        let assessment = matcher.assess_ai_watermark(&cover);
        assert!(assessment.is_some());
        let Some(assessment) = assessment else {
            return;
        };
        assert!(assessment.detected);
        assert_eq!(assessment.model_id.as_deref(), Some("test-ai"));
        assert_eq!(assessment.matched_strong_bins, 1);
        assert_eq!(assessment.total_strong_bins, 1);
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
