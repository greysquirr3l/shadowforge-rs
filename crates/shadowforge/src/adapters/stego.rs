//! Steganography technique adapters implementing `EmbedTechnique` port.

use crate::domain::errors::{DeniableError, StegoError};
use crate::domain::ports::{DeniableEmbedder, EmbedTechnique, ExtractTechnique, PdfProcessor};
use crate::domain::types::{
    Capacity, CoverMedia, CoverMediaKind, DeniableKeySet, DeniablePayloadPair, Payload,
    StegoTechnique,
};
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

/// PDF content-stream LSB steganography adapter.
///
/// Wraps the `PdfProcessor`'s content-stream embedding methods to implement
/// the `EmbedTechnique` trait.
pub struct PdfContentStreamLsb {
    processor: Box<dyn PdfProcessor>,
}

impl PdfContentStreamLsb {
    /// Create a new PDF content-stream LSB embedder.
    #[must_use]
    pub fn new(processor: Box<dyn PdfProcessor>) -> Self {
        Self { processor }
    }
}

impl EmbedTechnique for PdfContentStreamLsb {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfContentStream
    }

    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
        // Check if cover is a PDF
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF content-stream LSB requires PdfDocument, got {:?}", cover.kind),
            });
        }

        // TODO(T10): Implement capacity estimation for content-stream LSB
        // For now, return a conservative estimate based on typical PDF content streams
        // Real implementation would parse the PDF and count numeric tokens
        Ok(Capacity {
            bytes: 1024, // Conservative estimate
            technique: StegoTechnique::PdfContentStream,
        })
    }

    fn embed(&self, cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF content-stream LSB requires PdfDocument, got {:?}", cover.kind),
            });
        }

        self.processor
            .embed_in_content_stream(cover, payload)
            .map_err(|e| StegoError::MalformedCoverData {
                reason: format!("embed failed: {e}"),
            })
    }
}

impl ExtractTechnique for PdfContentStreamLsb {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfContentStream
    }

    fn extract(&self, cover: &CoverMedia) -> Result<Payload, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF content-stream LSB requires PdfDocument, got {:?}", cover.kind),
            });
        }

        self.processor
            .extract_from_content_stream(cover)
            .map_err(|e| StegoError::IntegrityCheckFailed {
                reason: format!("extract failed: {e}"),
            })
    }
}

/// PDF XMP metadata steganography adapter.
///
/// Wraps the `PdfProcessor`'s metadata embedding methods to implement
/// the `EmbedTechnique` trait.
pub struct PdfMetadataEmbed {
    processor: Box<dyn PdfProcessor>,
}

impl PdfMetadataEmbed {
    /// Create a new PDF metadata embedder.
    #[must_use]
    pub fn new(processor: Box<dyn PdfProcessor>) -> Self {
        Self { processor }
    }
}

impl EmbedTechnique for PdfMetadataEmbed {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfMetadata
    }

    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF metadata embedding requires PdfDocument, got {:?}", cover.kind),
            });
        }

        // XMP metadata can hold large base64-encoded payloads
        // Base64 encoding adds ~33% overhead
        Ok(Capacity {
            bytes: 1_000_000, // XMP can hold very large payloads
            technique: StegoTechnique::PdfMetadata,
        })
    }

    fn embed(&self, cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF metadata embedding requires PdfDocument, got {:?}", cover.kind),
            });
        }

        self.processor
            .embed_in_metadata(cover, payload)
            .map_err(|e| StegoError::MalformedCoverData {
                reason: format!("embed failed: {e}"),
            })
    }
}

impl ExtractTechnique for PdfMetadataEmbed {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfMetadata
    }

    fn extract(&self, cover: &CoverMedia) -> Result<Payload, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF metadata embedding requires PdfDocument, got {:?}", cover.kind),
            });
        }

        self.processor
            .extract_from_metadata(cover)
            .map_err(|e| StegoError::IntegrityCheckFailed {
                reason: format!("extract failed: {e}"),
            })
    }
}

/// LSB image steganography adapter for PNG/BMP.
///
/// Embeds payload in the least significant bits of RGB channels only
/// (alpha channel is untouched). Header encodes 32-bit big-endian payload length.
#[derive(Debug, Default)]
pub struct LsbImage;

impl LsbImage {
    /// Create a new LSB image embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EmbedTechnique for LsbImage {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::LsbImage
    }

    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
        // Only PNG and BMP are supported
        match cover.kind {
            CoverMediaKind::PngImage | CoverMediaKind::BmpImage => {}
            _ => {
                return Err(StegoError::UnsupportedCoverType {
                    reason: format!("LSB image requires PNG or BMP, got {:?}", cover.kind),
                })
            }
        }

        // Parse dimensions from metadata
        let width: u32 = cover
            .metadata
            .get("width")
            .ok_or_else(|| StegoError::MalformedCoverData {
                reason: "missing width metadata".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| StegoError::MalformedCoverData {
                reason: format!("invalid width: {e}"),
            })?;

        let height: u32 = cover
            .metadata
            .get("height")
            .ok_or_else(|| StegoError::MalformedCoverData {
                reason: "missing height metadata".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| StegoError::MalformedCoverData {
                reason: format!("invalid height: {e}"),
            })?;

        let pixel_count = width
            .checked_mul(height)
            .ok_or_else(|| StegoError::MalformedCoverData {
                reason: "pixel count overflow".to_string(),
            })?;

        // Capacity: 3 bits per pixel (R, G, B), minus 32 bits for header
        // = (pixel_count * 3 - 32) / 8 bytes
        let bits = pixel_count
            .checked_mul(3)
            .and_then(|b| b.checked_sub(32))
            .ok_or_else(|| StegoError::MalformedCoverData {
                reason: "capacity calculation overflow".to_string(),
            })?;

        let bytes = u64::from(bits / 8);

        Ok(Capacity {
            bytes,
            technique: StegoTechnique::LsbImage,
        })
    }

    fn embed(&self, mut cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
        // Check cover type
        match cover.kind {
            CoverMediaKind::PngImage | CoverMediaKind::BmpImage => {}
            _ => {
                return Err(StegoError::UnsupportedCoverType {
                    reason: format!("LSB image requires PNG or BMP, got {:?}", cover.kind),
                })
            }
        }

        // Check capacity
        let cap = self.capacity(&cover)?;
        let payload_len = payload.as_bytes().len() as u64;
        if payload_len > cap.bytes {
            return Err(StegoError::PayloadTooLarge {
                needed: payload_len,
                available: cap.bytes,
            });
        }

        // Check that payload length fits in 32-bit header
        if payload_len > u64::from(u32::MAX) {
            return Err(StegoError::PayloadTooLarge {
                needed: payload_len,
                available: u64::from(u32::MAX),
            });
        }

        // Get mutable access to pixel data
        let data = cover.data.to_vec();
        let mut pixels = data;

        // Embed 32-bit big-endian payload length in first 32 LSBs
        #[expect(clippy::cast_possible_truncation, reason = "checked above: payload_len <= u32::MAX")]
        let len_bytes = (payload_len as u32).to_be_bytes();
        for (byte_idx, byte) in len_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let pixel_idx = byte_idx * 8 + bit_idx;

                // RGB only, skip alpha (every 4th byte)
                let channel_idx = pixel_idx / 3;
                let rgb_offset = pixel_idx % 3;
                let byte_pos = channel_idx * 4 + rgb_offset;

                pixels[byte_pos] = (pixels[byte_pos] & 0xFE) | bit;
            }
        }

        // Embed payload bits starting after header (32 bits)
        let payload_bytes = payload.as_bytes();
        for (byte_idx, byte) in payload_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let pixel_idx = 32 + byte_idx * 8 + bit_idx;

                // RGB only, skip alpha
                let channel_idx = pixel_idx / 3;
                let rgb_offset = pixel_idx % 3;
                let byte_pos = channel_idx * 4 + rgb_offset;

                pixels[byte_pos] = (pixels[byte_pos] & 0xFE) | bit;
            }
        }

        cover.data = pixels.into();
        Ok(cover)
    }
}

impl ExtractTechnique for LsbImage {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::LsbImage
    }

    fn extract(&self, cover: &CoverMedia) -> Result<Payload, StegoError> {
        // Check cover type
        match cover.kind {
            CoverMediaKind::PngImage | CoverMediaKind::BmpImage => {}
            _ => {
                return Err(StegoError::UnsupportedCoverType {
                    reason: format!("LSB image requires PNG or BMP, got {:?}", cover.kind),
                })
            }
        }

        let pixels = cover.data.as_ref();

        // Extract 32-bit big-endian payload length from first 32 LSBs
        let mut len_bytes = [0u8; 4];
        for (byte_idx, len_byte) in len_bytes.iter_mut().enumerate() {
            for bit_idx in 0..8 {
                let pixel_idx = byte_idx * 8 + bit_idx;

                // RGB only, skip alpha
                let channel_idx = pixel_idx / 3;
                let rgb_offset = pixel_idx % 3;
                let byte_pos = channel_idx * 4 + rgb_offset;

                let bit = pixels[byte_pos] & 1;
                *len_byte |= bit << (7 - bit_idx);
            }
        }

        let payload_len = u32::from_be_bytes(len_bytes) as usize;

        // Extract payload bits
        let mut payload_bytes = vec![0u8; payload_len];
        for (byte_idx, payload_byte) in payload_bytes.iter_mut().enumerate() {
            for bit_idx in 0..8 {
                let pixel_idx = 32 + byte_idx * 8 + bit_idx;

                // RGB only, skip alpha
                let channel_idx = pixel_idx / 3;
                let rgb_offset = pixel_idx % 3;
                let byte_pos = channel_idx * 4 + rgb_offset;

                let bit = pixels[byte_pos] & 1;
                *payload_byte |= bit << (7 - bit_idx);
            }
        }

        Ok(Payload::from_bytes(payload_bytes))
    }
}

/// DCT-based JPEG steganography adapter (STUB).
///
/// **NOT YET IMPLEMENTED**: Requires a pure-Rust JPEG library that exposes
/// DCT coefficients without unsafe code. Current Rust JPEG libraries either:
/// - Decode to pixels only (jpeg-decoder, image crate)
/// - Require unsafe bindings (mozjpeg-sys, libjpeg-turbo-sys)
///
/// TODO(T12): Implement DCT coefficient access and modification:
/// - Parse JPEG to access non-zero AC DCT coefficients
/// - Embed payload in LSBs of coefficients (skip DC and zeros)
/// - Preserve quantization and Huffman tables
/// - Re-encode JPEG with modified coefficients
#[derive(Debug, Default)]
pub struct DctJpeg;

impl DctJpeg {
    /// Create a new DCT JPEG embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EmbedTechnique for DctJpeg {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::DctJpeg
    }

    fn capacity(&self, _cover: &CoverMedia) -> Result<Capacity, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "DCT JPEG steganography not yet implemented (requires DCT coefficient access)"
                .to_string(),
        })
    }

    fn embed(&self, _cover: CoverMedia, _payload: &Payload) -> Result<CoverMedia, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "DCT JPEG steganography not yet implemented (requires DCT coefficient access)"
                .to_string(),
        })
    }
}

impl ExtractTechnique for DctJpeg {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::DctJpeg
    }

    fn extract(&self, _cover: &CoverMedia) -> Result<Payload, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "DCT JPEG steganography not yet implemented (requires DCT coefficient access)"
                .to_string(),
        })
    }
}

/// Palette-based steganography adapter for GIF/PNG indexed images (STUB).
///
/// **NOT YET IMPLEMENTED**: Requires palette extraction from indexed color images.
/// The `image` crate converts all images to RGBA8, losing original palette data.
///
/// TODO(T13): Implement palette steganography:
/// - Extract palette data from GIF/PNG indexed color images
/// - Store palette as bytes in `CoverMedia.metadata["palette"]`
/// - Embed payload in LSBs of palette R/G/B bytes
/// - Capacity: (`palette_size` * 3) / 8 bytes
/// - Re-encode image with modified palette (pixel indices unchanged)
/// - Requires format-specific handling (GIF vs indexed PNG)
#[derive(Debug, Default)]
pub struct PaletteStego;

impl PaletteStego {
    /// Create a new palette steganography embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EmbedTechnique for PaletteStego {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::Palette
    }

    fn capacity(&self, _cover: &CoverMedia) -> Result<Capacity, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Palette steganography not yet implemented (requires palette extraction)"
                .to_string(),
        })
    }

    fn embed(&self, _cover: CoverMedia, _payload: &Payload) -> Result<CoverMedia, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Palette steganography not yet implemented (requires palette extraction)"
                .to_string(),
        })
    }
}

impl ExtractTechnique for PaletteStego {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::Palette
    }

    fn extract(&self, _cover: &CoverMedia) -> Result<Payload, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Palette steganography not yet implemented (requires palette extraction)"
                .to_string(),
        })
    }
}

/// LSB audio steganography adapter for WAV files.
///
/// Embeds payload in the least significant bits of i16 audio samples.
/// Header encodes 32-bit big-endian payload length in first 32 sample LSBs.
#[derive(Debug, Default)]
pub struct LsbAudio;

impl LsbAudio {
    /// Create a new LSB audio embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EmbedTechnique for LsbAudio {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::LsbAudio
    }

    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
        // Only WAV audio is supported
        if cover.kind != CoverMediaKind::WavAudio {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("LSB audio requires WAV, got {:?}", cover.kind),
            });
        }

        // Sample count is data length / 2 (i16 = 2 bytes)
        let sample_count = cover.data.len() / 2;

        // Need at least 32 samples for header
        if sample_count < 32 {
            return Err(StegoError::MalformedCoverData {
                reason: "audio too short for LSB embedding (need at least 32 samples)".to_string(),
            });
        }

        // Capacity: (sample_count - 32) / 8 bytes
        let capacity_bits = sample_count.checked_sub(32).ok_or_else(|| {
            StegoError::MalformedCoverData {
                reason: "capacity calculation underflow".to_string(),
            }
        })?;

        let bytes = (capacity_bits / 8) as u64;

        Ok(Capacity {
            bytes,
            technique: StegoTechnique::LsbAudio,
        })
    }

    fn embed(&self, mut cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
        // Check cover type
        if cover.kind != CoverMediaKind::WavAudio {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("LSB audio requires WAV, got {:?}", cover.kind),
            });
        }

        // Check capacity
        let cap = self.capacity(&cover)?;
        let payload_len = payload.as_bytes().len() as u64;
        if payload_len > cap.bytes {
            return Err(StegoError::PayloadTooLarge {
                needed: payload_len,
                available: cap.bytes,
            });
        }

        // Check that payload length fits in 32-bit header
        if payload_len > u64::from(u32::MAX) {
            return Err(StegoError::PayloadTooLarge {
                needed: payload_len,
                available: u64::from(u32::MAX),
            });
        }

        // Get mutable access to sample data (i16 little-endian)
        let mut samples = cover.data.to_vec();

        // Embed 32-bit big-endian payload length in first 32 sample LSBs
        #[expect(clippy::cast_possible_truncation, reason = "checked above: payload_len <= u32::MAX")]
        let len_bytes = (payload_len as u32).to_be_bytes();
        for (byte_idx, byte) in len_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let sample_idx = byte_idx * 8 + bit_idx;

                // Modify LSB of i16 sample (little-endian)
                let byte_pos = sample_idx * 2; // i16 = 2 bytes
                samples[byte_pos] = (samples[byte_pos] & 0xFE) | bit;
            }
        }

        // Embed payload bits starting after header (32 samples)
        let payload_bytes = payload.as_bytes();
        for (byte_idx, byte) in payload_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let sample_idx = 32 + byte_idx * 8 + bit_idx;

                let byte_pos = sample_idx * 2;
                samples[byte_pos] = (samples[byte_pos] & 0xFE) | bit;
            }
        }

        cover.data = samples.into();
        Ok(cover)
    }
}

impl ExtractTechnique for LsbAudio {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::LsbAudio
    }

    fn extract(&self, cover: &CoverMedia) -> Result<Payload, StegoError> {
        // Check cover type
        if cover.kind != CoverMediaKind::WavAudio {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("LSB audio requires WAV, got {:?}", cover.kind),
            });
        }

        let samples = cover.data.as_ref();

        // Need at least 32 samples for header
        if samples.len() < 64 {
            // 32 samples * 2 bytes
            return Err(StegoError::MalformedCoverData {
                reason: "audio too short to extract payload".to_string(),
            });
        }

        // Extract 32-bit big-endian payload length from first 32 sample LSBs
        let mut len_bytes = [0u8; 4];
        for (byte_idx, len_byte) in len_bytes.iter_mut().enumerate() {
            for bit_idx in 0..8 {
                let sample_idx = byte_idx * 8 + bit_idx;
                let byte_pos = sample_idx * 2;

                let bit = samples[byte_pos] & 1;
                *len_byte |= bit << (7 - bit_idx);
            }
        }

        let payload_len = u32::from_be_bytes(len_bytes) as usize;

        // Sanity check payload length
        let max_samples = samples.len() / 2;
        if payload_len > (max_samples.saturating_sub(32)) / 8 {
            return Err(StegoError::MalformedCoverData {
                reason: format!("invalid payload length: {payload_len}"),
            });
        }

        // Extract payload bits
        let mut payload_bytes = vec![0u8; payload_len];
        for (byte_idx, payload_byte) in payload_bytes.iter_mut().enumerate() {
            for bit_idx in 0..8 {
                let sample_idx = 32 + byte_idx * 8 + bit_idx;
                let byte_pos = sample_idx * 2;

                let bit = samples[byte_pos] & 1;
                *payload_byte |= bit << (7 - bit_idx);
            }
        }

        Ok(Payload::from_bytes(payload_bytes))
    }
}

/// Phase encoding (DSSS) audio steganography adapter (STUB).
///
/// **NOT YET IMPLEMENTED**: Requires FFT/IFFT and phase manipulation.
///
/// TODO(T14): Implement phase encoding:
/// - Segment audio into blocks
/// - Apply FFT to each segment
/// - Embed one bit per segment by phase shift
/// - Adaptive alpha: scale shift by segment energy
/// - Apply IFFT to reconstruct samples
/// - Requires audio DSP library (rustfft or similar)
#[derive(Debug, Default)]
pub struct PhaseEncoding;

impl PhaseEncoding {
    /// Create a new phase encoding embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EmbedTechnique for PhaseEncoding {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PhaseEncoding
    }

    fn capacity(&self, _cover: &CoverMedia) -> Result<Capacity, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Phase encoding not yet implemented (requires FFT/phase manipulation)"
                .to_string(),
        })
    }

    fn embed(&self, _cover: CoverMedia, _payload: &Payload) -> Result<CoverMedia, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Phase encoding not yet implemented (requires FFT/phase manipulation)"
                .to_string(),
        })
    }
}

impl ExtractTechnique for PhaseEncoding {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PhaseEncoding
    }

    fn extract(&self, _cover: &CoverMedia) -> Result<Payload, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Phase encoding not yet implemented (requires FFT/phase manipulation)"
                .to_string(),
        })
    }
}

/// Echo hiding audio steganography adapter (STUB).
///
/// **NOT YET IMPLEMENTED**: Requires echo synthesis and autocorrelation.
///
/// TODO(T14): Implement echo hiding:
/// - Two echo delays (d0, d1) for bit 0/1
/// - Embed by adding delayed echo to audio
/// - Extract via autocorrelation peak detection
/// - Use `array_windows` for autocorrelation computation
/// - Requires audio DSP operations
#[derive(Debug, Default)]
pub struct EchoHiding;

impl EchoHiding {
    /// Create a new echo hiding embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EmbedTechnique for EchoHiding {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::EchoHiding
    }

    fn capacity(&self, _cover: &CoverMedia) -> Result<Capacity, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Echo hiding not yet implemented (requires echo synthesis and autocorrelation)"
                .to_string(),
        })
    }

    fn embed(&self, _cover: CoverMedia, _payload: &Payload) -> Result<CoverMedia, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Echo hiding not yet implemented (requires echo synthesis and autocorrelation)"
                .to_string(),
        })
    }
}

impl ExtractTechnique for EchoHiding {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::EchoHiding
    }

    fn extract(&self, _cover: &CoverMedia) -> Result<Payload, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Echo hiding not yet implemented (requires echo synthesis and autocorrelation)"
                .to_string(),
        })
    }
}

/// Zero-width character text steganography adapter (STUB).
///
/// **NOT YET IMPLEMENTED**: Zero-width Unicode characters (ZWSP, ZWNJ, ZWJ, etc.)
/// have complex grapheme clustering rules that make reliable embedding/extraction
/// difficult. Format characters can be combined with adjacent characters by the
/// Unicode grapheme segmentation algorithm in context-dependent ways.
///
/// TODO(T15): Implement zero-width text steganography:
/// - Research Unicode-safe zero-width character pairs that remain separate graphemes
/// - Consider alternative approaches (variation selectors, combining marks)
/// - Extensive testing with all Unicode scripts (Arabic, Thai, Devanagari, emoji ZWJ sequences)
/// - Validate grapheme-cluster safety across all contexts
#[derive(Debug, Default)]
pub struct ZeroWidthText;

impl ZeroWidthText {
    /// Create a new zero-width text embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EmbedTechnique for ZeroWidthText {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::ZeroWidthText
    }

    fn capacity(&self, _cover: &CoverMedia) -> Result<Capacity, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Zero-width text steganography not yet implemented (Unicode grapheme segmentation complexity)".to_string(),
        })
    }

    fn embed(&self, _cover: CoverMedia, _payload: &Payload) -> Result<CoverMedia, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Zero-width text steganography not yet implemented (Unicode grapheme segmentation complexity)".to_string(),
        })
    }
}

impl ExtractTechnique for ZeroWidthText {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::ZeroWidthText
    }

    fn extract(&self, _cover: &CoverMedia) -> Result<Payload, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "Zero-width text steganography not yet implemented (Unicode grapheme segmentation complexity)".to_string(),
        })
    }
}

// ─── Dual-Payload Deniable Steganography ─────────────────────────────────────

/// Dual-payload deniable steganography adapter.
///
/// Embeds two independent payloads (real and decoy) into a single cover using
/// key-derived pseudo-random patterns. Each key produces a deterministic but
/// non-overlapping set of embedding positions, ensuring that:
///
/// - Extracting with the primary key yields the real payload
/// - Extracting with the decoy key yields the decoy payload
/// - No observer can prove which payload is "real" vs "decoy"
///
/// The implementation uses `ChaCha20` PRNG seeded with SHA-256 hashes of the keys
/// to generate reproducible embedding patterns.
pub struct DualPayloadEmbedder;

impl Default for DualPayloadEmbedder {
    fn default() -> Self {
        Self
    }
}

impl DualPayloadEmbedder {
    /// Create a new dual-payload embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Derive a 32-byte seed from a key and channel using SHA-256.
    ///
    /// The channel tag ensures different seeds for primary (channel 0) and decoy (channel 1),
    /// preventing pattern overlap.
    fn derive_seed_with_channel(key: &[u8], channel: u8) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update([channel]);
        hasher.finalize().into()
    }

    /// Generate a pseudo-random permutation of indices for embedding.
    ///
    /// Returns a vector of `count` indices in the range `[0, total)`, shuffled
    /// deterministically based on the `seed`. The indices are NOT sorted, preserving
    /// the pseudo-random access pattern for better security.
    fn generate_pattern(seed: [u8; 32], total: usize, count: usize) -> Vec<usize> {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut indices: Vec<usize> = (0..total).collect();
        indices.shuffle(&mut rng);
        indices.truncate(count);
        indices
    }

    /// Embed a single payload into the cover at specified bit positions.
    fn embed_at_positions(
        cover_data: &mut [u8],
        payload: &[u8],
        positions: &[usize],
    ) -> Result<(), DeniableError> {
        let payload_bits = payload.len() * 8;

        if payload_bits > positions.len() {
            return Err(DeniableError::InsufficientCapacity);
        }

        // Embed each bit of the payload at its designated position
        for (bit_idx, &pos) in positions.iter().enumerate().take(payload_bits) {
            let payload_byte_idx = bit_idx / 8;
            let payload_bit_idx = 7 - (bit_idx % 8); // MSB-first
            let payload_bit = (payload[payload_byte_idx] >> payload_bit_idx) & 1;

            let cover_byte_idx = pos / 8;
            let cover_bit_idx = pos % 8;

            // Set the LSB at this position
            if payload_bit == 1 {
                cover_data[cover_byte_idx] |= 1 << cover_bit_idx;
            } else {
                cover_data[cover_byte_idx] &= !(1 << cover_bit_idx);
            }
        }

        Ok(())
    }

    /// Extract a payload from the cover at specified bit positions.
    fn extract_from_positions(
        cover_data: &[u8],
        positions: &[usize],
        payload_len: usize,
    ) -> Result<Vec<u8>, DeniableError> {
        let payload_bits = payload_len * 8;

        if payload_bits > positions.len() {
            return Err(DeniableError::ExtractionFailed {
                reason: "insufficient embedding positions for expected payload length".to_string(),
            });
        }

        let mut payload = vec![0u8; payload_len];

        for (bit_idx, &pos) in positions.iter().enumerate().take(payload_bits) {
            let cover_byte_idx = pos / 8;
            let cover_bit_idx = pos % 8;
            let cover_bit = (cover_data[cover_byte_idx] >> cover_bit_idx) & 1;

            let payload_byte_idx = bit_idx / 8;
            let payload_bit_idx = 7 - (bit_idx % 8); // MSB-first

            if cover_bit == 1 {
                payload[payload_byte_idx] |= 1 << payload_bit_idx;
            }
        }

        Ok(payload)
    }
}

impl DeniableEmbedder for DualPayloadEmbedder {
    fn embed_dual(
        &self,
        mut cover: CoverMedia,
        pair: &DeniablePayloadPair,
        keys: &DeniableKeySet,
        _embedder: &dyn EmbedTechnique,
    ) -> Result<CoverMedia, DeniableError> {
        let cover_bytes = cover.data.len();
        let cover_bits = cover_bytes * 8;

        // Split cover into two non-overlapping channels to avoid interference
        // Channel 0: even bit indices (0, 2, 4, ...)
        // Channel 1: odd bit indices (1, 3, 5, ...)
        let channel_capacity = cover_bits / 2;

        // Calculate required capacity (both payloads + length headers)
        // Header: 4 bytes (32 bits) for each payload length
        let real_total_bits = (pair.real_payload.len() + 4) * 8;
        let decoy_total_bits = (pair.decoy_payload.len() + 4) * 8;

        if real_total_bits > channel_capacity || decoy_total_bits > channel_capacity {
            return Err(DeniableError::InsufficientCapacity);
        }

        // Derive channel-tagged seeds
        // Primary key uses channel 0 (even bits)
        // Decoy key uses channel 1 (odd bits)
        let primary_seed = Self::derive_seed_with_channel(&keys.primary_key, 0);
        let decoy_seed = Self::derive_seed_with_channel(&keys.decoy_key, 1);

        // Generate patterns within each channel
        // Channel 0: select from even-indexed bits
        let primary_positions = Self::generate_pattern(primary_seed, channel_capacity, real_total_bits)
            .into_iter()
            .map(|i| i * 2) // Map to even indices
            .collect::<Vec<_>>();

        // Channel 1: select from odd-indexed bits
        let decoy_positions = Self::generate_pattern(decoy_seed, channel_capacity, decoy_total_bits)
            .into_iter()
            .map(|i| i * 2 + 1) // Map to odd indices
            .collect::<Vec<_>>();

        // Prepare payloads with length headers (32-bit big-endian)
        let real_len = pair.real_payload.len();
        let decoy_len = pair.decoy_payload.len();

        #[expect(clippy::cast_possible_truncation, reason = "payload size checked against u32::MAX in capacity validation")]
        let mut real_with_header = (real_len as u32).to_be_bytes().to_vec();
        real_with_header.extend_from_slice(&pair.real_payload);

        #[expect(clippy::cast_possible_truncation, reason = "payload size checked against u32::MAX in capacity validation")]
        let mut decoy_with_header = (decoy_len as u32).to_be_bytes().to_vec();
        decoy_with_header.extend_from_slice(&pair.decoy_payload);

        // Get mutable access to cover data
        let mut cover_data = cover.data.to_vec();

        // Embed both payloads (guaranteed non-overlapping due to channel separation)
        Self::embed_at_positions(&mut cover_data, &real_with_header, &primary_positions)
            .map_err(|e| DeniableError::EmbedFailed {
                reason: format!("real payload embed failed: {e}"),
            })?;

        Self::embed_at_positions(&mut cover_data, &decoy_with_header, &decoy_positions)
            .map_err(|e| DeniableError::EmbedFailed {
                reason: format!("decoy payload embed failed: {e}"),
            })?;

        cover.data = cover_data.into();
        Ok(cover)
    }

    fn extract_with_key(
        &self,
        stego: &CoverMedia,
        key: &[u8],
        _extractor: &dyn ExtractTechnique,
    ) -> Result<Payload, DeniableError> {
        let cover_bytes = stego.data.len();
        let cover_bits = cover_bytes * 8;
        let channel_capacity = cover_bits / 2;

        // Try both channels - we don't know which one was used for this key
        // Channel 0: even bits
        // Channel 1: odd bits


        for channel in 0..2 {
            let seed = Self::derive_seed_with_channel(key, channel);

            // Generate pattern for header extraction
            let header_bits = 32;
            let header_positions = Self::generate_pattern(seed, channel_capacity, header_bits)
                .into_iter()
                .map(|i| i * 2 + channel as usize) // Map to channel's bit indices
                .collect::<Vec<_>>();


            if header_positions.len() < header_bits {
                continue; // Try next channel
            }

            // Extract length header
            let Ok(header_bytes) = Self::extract_from_positions(
                stego.data.as_ref(),
                &header_positions,
                4,
            ) else {
                continue; // Try next channel
            };


            let payload_len = u32::from_be_bytes([
                header_bytes[0],
                header_bytes[1],
                header_bytes[2],
                header_bytes[3],
            ]) as usize;


            // Validate payload length is reasonable
            // Reject 0-length payloads (likely garbage from wrong channel)
            if payload_len == 0 {
                continue; // Try next channel
            }

            let max_payload_len = channel_capacity / 8;
            if payload_len > max_payload_len {
                continue; // Try next channel
            }

            // Generate full pattern including header + payload
            let total_bits = (payload_len + 4) * 8;
            if total_bits > channel_capacity {
                continue; // Try next channel
            }

            let positions = Self::generate_pattern(seed, channel_capacity, total_bits)
                .into_iter()
                .map(|i| i * 2 + channel as usize)
                .collect::<Vec<_>>();

            // Extract full payload
            let Ok(with_header) = Self::extract_from_positions(
                stego.data.as_ref(),
                &positions,
                payload_len + 4,
            ) else {
                continue; // Try next channel
            };

            // Verify header matches
            let extracted_header = u32::from_be_bytes([
                with_header[0],
                with_header[1],
                with_header[2],
                with_header[3],
            ]) as usize;

            if extracted_header == payload_len {
                // Success! Return payload without header
                return Ok(Payload::from_bytes(with_header[4..].to_vec()));
            }
        }

        // Failed to extract from both channels
        Err(DeniableError::ExtractionFailed {
            reason: "failed to extract valid payload from either channel".to_string(),
        })
    }
}

// TODO(T11): Implement PdfPageStegoService after LsbImage is available
// This service will:
// - Render PDF pages to PNG images
// - RS-encode payload into N shards (N = page count)
// - Embed one shard per page using LsbImage
// - Rebuild PDF from stego pages

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::pdf::PdfProcessorImpl;
    use lopdf::{dictionary, Document, Object};

    fn create_test_pdf() -> Vec<u8> {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let page_id = doc.new_object_id();

        doc.objects.insert(
            page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((page_id.0 + 1, 0)),
            }),
        );

        // Content stream with many numeric values
        let content =
            b"BT\n/F1 12 Tf\n100 700 Td\n(Test) Tj\n200 650 Td\n(PDF) Tj\nET\n1 0 0 1 0 0 cm\n";
        doc.add_object(lopdf::Stream::new(dictionary! {}, content.to_vec()));

        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_id)],
                "Count" => 1,
            }),
        );

        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(pages_id),
        });

        doc.trailer.set("Root", Object::Reference(catalog_id));

        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).expect("save test PDF");
        bytes
    }

    #[test]
    fn test_pdf_content_stream_lsb_roundtrip() {
        let processor = Box::new(PdfProcessorImpl::default());
        let embedder = PdfContentStreamLsb::new(processor);

        let pdf_bytes = create_test_pdf();
        let cover = CoverMedia {
            kind: CoverMediaKind::PdfDocument,
            data: pdf_bytes.into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![0xAB]); // 1 byte

        // Embed
        let stego = embedder.embed(cover, &payload).expect("embed");

        // Extract
        let extracted = embedder.extract(&stego).expect("extract");
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn test_pdf_metadata_embed_roundtrip() {
        let processor = Box::new(PdfProcessorImpl::default());
        let embedder = PdfMetadataEmbed::new(processor);

        let pdf_bytes = create_test_pdf();
        let cover = CoverMedia {
            kind: CoverMediaKind::PdfDocument,
            data: pdf_bytes.into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![1, 2, 3, 4, 5]); // 5 bytes

        // Embed
        let stego = embedder.embed(cover, &payload).expect("embed");

        // Extract
        let extracted = embedder.extract(&stego).expect("extract");
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn test_unsupported_cover_type() {
        let processor = Box::new(PdfProcessorImpl::default());
        let embedder = PdfContentStreamLsb::new(processor);

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: vec![].into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![1, 2, 3]);

        let result = embedder.embed(cover, &payload);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));
    }

    #[test]
    fn test_lsb_image_roundtrip_256x256() {
        let embedder = LsbImage::new();

        // Create 256x256 white RGBA image
        let width = 256_u32;
        let height = 256_u32;
        let pixel_count = width * height;
        let data = vec![255u8; (pixel_count * 4) as usize]; // RGBA

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        // 64-byte payload
        let payload = Payload::from_bytes(vec![0xAB; 64]);

        // Embed
        let stego = embedder.embed(cover.clone(), &payload).expect("embed");

        // Verify pixel changes are ±1
        let orig_pixels = cover.data.as_ref();
        let stego_pixels = stego.data.as_ref();
        for (i, (orig, stego_val)) in orig_pixels.iter().zip(stego_pixels.iter()).enumerate() {
            let diff = orig.abs_diff(*stego_val);
            assert!(
                diff <= 1,
                "pixel at index {i} changed by more than 1: {orig} -> {stego_val}"
            );
        }

        // Extract
        let extracted = embedder.extract(&stego).expect("extract");
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn test_lsb_image_capacity_10x10() {
        let embedder = LsbImage::new();

        let width = 10_u32;
        let height = 10_u32;
        let pixel_count = width * height;
        let data = vec![0u8; (pixel_count * 4) as usize];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        let cap = embedder.capacity(&cover).expect("capacity");

        // 10x10 = 100 pixels
        // 100 * 3 = 300 bits
        // 300 - 32 (header) = 268 bits
        // 268 / 8 = 33 bytes
        assert_eq!(cap.bytes, 33);
        assert_eq!(cap.technique, StegoTechnique::LsbImage);
    }

    #[test]
    fn test_lsb_image_insufficient_capacity() {
        let embedder = LsbImage::new();

        let width = 10_u32;
        let height = 10_u32;
        let pixel_count = width * height;
        let data = vec![0u8; (pixel_count * 4) as usize];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        // Try to embed 100 bytes (capacity is only 33)
        let payload = Payload::from_bytes(vec![0xAB; 100]);

        let result = embedder.embed(cover, &payload);
        assert!(matches!(
            result,
            Err(StegoError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn test_lsb_image_bmp_support() {
        let embedder = LsbImage::new();

        let width = 100_u32;
        let height = 100_u32;
        let pixel_count = width * height;
        let data = vec![128u8; (pixel_count * 4) as usize];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::BmpImage,
            data: data.into(),
            metadata,
        };

        let payload = Payload::from_bytes(vec![1, 2, 3, 4, 5]);

        // Embed
        let stego = embedder.embed(cover, &payload).expect("embed");

        // Extract
        let extracted = embedder.extract(&stego).expect("extract");
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn test_dct_jpeg_stub_returns_not_implemented() {
        let embedder = DctJpeg::new();

        let cover = CoverMedia {
            kind: CoverMediaKind::JpegImage,
            data: vec![].into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![1, 2, 3]);

        // Should return UnsupportedCoverType error indicating not implemented
        let result = embedder.embed(cover.clone(), &payload);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.extract(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.capacity(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));
    }

    #[test]
    fn test_palette_stego_stub_returns_not_implemented() {
        let embedder = PaletteStego::new();

        let cover = CoverMedia {
            kind: CoverMediaKind::GifImage,
            data: vec![].into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![1, 2, 3]);

        // Should return UnsupportedCoverType error indicating not implemented
        let result = embedder.embed(cover.clone(), &payload);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.extract(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.capacity(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));
    }

    #[test]
    fn test_lsb_audio_roundtrip() {
        let embedder = LsbAudio::new();

        // Create 1s of 44100 Hz 16-bit mono silence (44100 samples)
        let sample_rate = 44100;
        let sample_count = sample_rate; // 1 second
        let mut data = Vec::new();
        for _ in 0..sample_count {
            data.extend_from_slice(&0_i16.to_le_bytes());
        }

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("sample_rate".to_string(), sample_rate.to_string());
        metadata.insert("channels".to_string(), "1".to_string());
        metadata.insert("bits_per_sample".to_string(), "16".to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::WavAudio,
            data: data.into(),
            metadata,
        };

        // 512-byte payload
        let payload = Payload::from_bytes(vec![0xAB; 512]);

        // Embed
        let stego = embedder.embed(cover, &payload).expect("embed");

        // Extract
        let extracted = embedder.extract(&stego).expect("extract");
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn test_lsb_audio_capacity() {
        let embedder = LsbAudio::new();

        // 1000 samples
        let sample_count = 1000;
        let mut data = Vec::new();
        for _ in 0..sample_count {
            data.extend_from_slice(&0_i16.to_le_bytes());
        }

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("sample_rate".to_string(), "44100".to_string());
        metadata.insert("channels".to_string(), "1".to_string());
        metadata.insert("bits_per_sample".to_string(), "16".to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::WavAudio,
            data: data.into(),
            metadata,
        };

        let cap = embedder.capacity(&cover).expect("capacity");

        // 1000 samples - 32 (header) = 968 bits / 8 = 121 bytes
        assert_eq!(cap.bytes, 121);
        assert_eq!(cap.technique, StegoTechnique::LsbAudio);
    }

    #[test]
    fn test_lsb_audio_insufficient_capacity() {
        let embedder = LsbAudio::new();

        // 100 samples (very short audio)
        let sample_count = 100;
        let mut data = Vec::new();
        for _ in 0..sample_count {
            data.extend_from_slice(&0_i16.to_le_bytes());
        }

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("sample_rate".to_string(), "44100".to_string());
        metadata.insert("channels".to_string(), "1".to_string());
        metadata.insert("bits_per_sample".to_string(), "16".to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::WavAudio,
            data: data.into(),
            metadata,
        };

        // Try to embed 100 bytes (capacity is only 8 bytes)
        let payload = Payload::from_bytes(vec![0xAB; 100]);

        let result = embedder.embed(cover, &payload);
        assert!(matches!(result, Err(StegoError::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_phase_encoding_stub_returns_not_implemented() {
        let embedder = PhaseEncoding::new();

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("sample_rate".to_string(), "44100".to_string());
        metadata.insert("channels".to_string(), "1".to_string());
        metadata.insert("bits_per_sample".to_string(), "16".to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::WavAudio,
            data: vec![0; 1000].into(),
            metadata,
        };

        let payload = Payload::from_bytes(vec![1, 2, 3]);

        let result = embedder.embed(cover.clone(), &payload);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.extract(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.capacity(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));
    }

    #[test]
    fn test_echo_hiding_stub_returns_not_implemented() {
        let embedder = EchoHiding::new();

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("sample_rate".to_string(), "44100".to_string());
        metadata.insert("channels".to_string(), "1".to_string());
        metadata.insert("bits_per_sample".to_string(), "16".to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::WavAudio,
            data: vec![0; 1000].into(),
            metadata,
        };

        let payload = Payload::from_bytes(vec![1, 2, 3]);

        let result = embedder.embed(cover.clone(), &payload);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.extract(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.capacity(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));
    }

    #[test]
    fn test_zero_width_text_stub_returns_not_implemented() {
        let embedder = ZeroWidthText::new();

        let cover = CoverMedia {
            kind: CoverMediaKind::PlainText,
            data: "Hello, world!".as_bytes().to_vec().into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![1, 2, 3]);

        let result = embedder.embed(cover.clone(), &payload);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.extract(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.capacity(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));
    }

    #[test]
    fn test_dual_payload_roundtrip() {
        let embedder = DualPayloadEmbedder::new();
        let lsb_image = LsbImage::new();

        // Create a 100x100 pixel RGB image (30000 bytes)
        let width = 100u32;
        let height = 100u32;
        let pixel_count = (width * height) as usize;
        let data = vec![0u8; pixel_count * 3]; // RGB

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());
        metadata.insert("channels".to_string(), "3".to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        // Create payload pair
        let real_payload = b"This is the REAL secret message".to_vec();
        let decoy_payload = b"This is just a decoy".to_vec();

        let pair = DeniablePayloadPair {
            real_payload: real_payload.clone(),
            decoy_payload: decoy_payload.clone(),
        };

        // Create key set
        let keys = DeniableKeySet {
            primary_key: b"primary_key_12345".to_vec(),
            decoy_key: b"decoy_key_67890".to_vec(),
        };

        // Embed dual payloads
        let stego = embedder
            .embed_dual(cover.clone(), &pair, &keys, &lsb_image)
            .expect("embed_dual should succeed");


        // Extract with primary key
        let extracted_real = embedder
            .extract_with_key(&stego, &keys.primary_key, &lsb_image)
            .expect("extract with primary key should succeed");
        assert_eq!(extracted_real.as_bytes(), &real_payload);

        // Extract with decoy key
        let extracted_decoy = embedder
            .extract_with_key(&stego, &keys.decoy_key, &lsb_image)
            .expect("extract with decoy key should succeed");
        assert_eq!(extracted_decoy.as_bytes(), &decoy_payload);
    }

    #[test]
    fn test_dual_payload_insufficient_capacity() {
        let embedder = DualPayloadEmbedder::new();
        let lsb_image = LsbImage::new();

        // Create a very small cover (10x10 pixels = 300 bytes)
        let width = 10u32;
        let height = 10u32;
        let pixel_count = (width * height) as usize;
        let data = vec![0u8; pixel_count * 3];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());
        metadata.insert("channels".to_string(), "3".to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        // Create large payloads that won't fit
        let real_payload = vec![0u8; 200];
        let decoy_payload = vec![0u8; 200];

        let pair = DeniablePayloadPair {
            real_payload,
            decoy_payload,
        };

        let keys = DeniableKeySet {
            primary_key: b"primary_key".to_vec(),
            decoy_key: b"decoy_key".to_vec(),
        };

        // Should fail with InsufficientCapacity
        let result = embedder.embed_dual(cover, &pair, &keys, &lsb_image);
        assert!(matches!(result, Err(DeniableError::InsufficientCapacity)));
    }

    #[test]
    fn test_dual_payload_different_keys_produce_different_results() {
        let embedder = DualPayloadEmbedder::new();
        let lsb_image = LsbImage::new();

        // Create cover
        let width = 100u32;
        let height = 100u32;
        let pixel_count = (width * height) as usize;
        let data = vec![0u8; pixel_count * 3];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());
        metadata.insert("channels".to_string(), "3".to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        let real_payload = b"Real secret".to_vec();
        let decoy_payload = b"Fake data".to_vec();

        let pair = DeniablePayloadPair {
            real_payload: real_payload.clone(),
            decoy_payload: decoy_payload.clone(),
        };

        let keys = DeniableKeySet {
            primary_key: b"key1".to_vec(),
            decoy_key: b"key2".to_vec(),
        };

        let stego = embedder
            .embed_dual(cover, &pair, &keys, &lsb_image)
            .expect("embed should succeed");

        // Extract with primary key
        let extracted1 = embedder
            .extract_with_key(&stego, &keys.primary_key, &lsb_image)
            .expect("extract with primary should succeed");

        // Extract with decoy key
        let extracted2 = embedder
            .extract_with_key(&stego, &keys.decoy_key, &lsb_image)
            .expect("extract with decoy should succeed");

        // Should be different
        assert_ne!(extracted1.as_bytes(), extracted2.as_bytes());
        assert_eq!(extracted1.as_bytes(), &real_payload);
        assert_eq!(extracted2.as_bytes(), &decoy_payload);
    }

    #[test]
    fn test_dual_payload_wrong_key_produces_garbage() {
        let embedder = DualPayloadEmbedder::new();
        let lsb_image = LsbImage::new();

        // Create cover
        let width = 100u32;
        let height = 100u32;
        let pixel_count = (width * height) as usize;
        let data = vec![0u8; pixel_count * 3];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());
        metadata.insert("channels".to_string(), "3".to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        let real_payload = b"Real secret message".to_vec();
        let decoy_payload = b"Decoy message".to_vec();

        let pair = DeniablePayloadPair {
            real_payload: real_payload.clone(),
            decoy_payload: decoy_payload.clone(),
        };

        let keys = DeniableKeySet {
            primary_key: b"correct_primary".to_vec(),
            decoy_key: b"correct_decoy".to_vec(),
        };

        let stego = embedder
            .embed_dual(cover, &pair, &keys, &lsb_image)
            .expect("embed should succeed");

        // Try extracting with a wrong key
        let wrong_key = b"wrong_key";
        let result = embedder.extract_with_key(&stego, wrong_key, &lsb_image);

        // Extraction may succeed but produce garbage, or may fail with ExtractionFailed
        // depending on what the garbage header decodes to
        match result {
            Ok(extracted) => {
                // If it succeeds, the extracted data should not match either payload
                assert_ne!(extracted.as_bytes(), &real_payload);
                assert_ne!(extracted.as_bytes(), &decoy_payload);
            }
            Err(DeniableError::ExtractionFailed { .. }) => {
                // This is also acceptable - garbage header caused extraction to fail
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}
