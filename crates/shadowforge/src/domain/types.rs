//! Canonical type vocabulary shared across all bounded contexts.
//!
//! This module defines every shared value object and entity referenced by
//! all bounded contexts. It contains **zero I/O dependencies** — no file
//! system, no network, no async runtime.

use std::collections::HashMap;
use std::path::PathBuf;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Payload ──────────────────────────────────────────────────────────────────

/// An arbitrary binary payload to be hidden inside a cover medium.
///
/// Zeroized on drop to prevent plaintext leaking into freed memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Payload(Vec<u8>);

impl Payload {
    /// Construct from raw bytes.
    #[must_use]
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Self {
        Self(data.into())
    }

    /// Construct from a UTF-8 string slice.
    ///
    /// # Errors
    /// Returns `Err` if `s` is not valid UTF-8 (infallible for `&str`, but
    /// provided for parity with byte-slice callers).
    #[must_use]
    pub fn from_str_utf8(s: &str) -> Result<Self, std::convert::Infallible> {
        Ok(Self(s.as_bytes().to_vec()))
    }

    /// Return the raw bytes of the payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the length of the payload in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if the payload is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("len", &self.0.len())
            .finish()
    }
}

// ─── CoverMediaKind ───────────────────────────────────────────────────────────

/// Discriminates cover medium types supported by shadowforge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CoverMediaKind {
    /// Portable Network Graphics image.
    PngImage,
    /// Windows Bitmap image.
    BmpImage,
    /// JPEG compressed image.
    JpegImage,
    /// GIF animated or static image.
    GifImage,
    /// WAV uncompressed audio.
    WavAudio,
    /// PDF document (first-class cover medium).
    PdfDocument,
    /// Plain UTF-8 text (for zero-width text stego).
    PlainText,
}

// ─── CoverMedia ───────────────────────────────────────────────────────────────

/// A decoded cover medium ready for steganographic embedding.
///
/// `data` holds raw decoded pixels (RGBA8) or samples — **not** file bytes.
/// Loading from disk is an adapter concern ([`crate::adapters`]).
#[derive(Debug, Clone)]
pub struct CoverMedia {
    /// The type of cover medium.
    pub kind: CoverMediaKind,
    /// Raw decoded content (pixels, samples, etc.).
    pub data: Bytes,
    /// Optional metadata key/value pairs (EXIF, comments, …).
    pub metadata: HashMap<String, String>,
}

// ─── StegoTechnique ───────────────────────────────────────────────────────────

/// Steganographic technique selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StegoTechnique {
    /// Least-significant-bit substitution in PNG/BMP pixel data.
    LsbImage,
    /// Quantisation index modulation on JPEG DCT AC coefficients.
    DctJpeg,
    /// Colour-palette index substitution for GIF/PNG indexed images.
    Palette,
    /// Least-significant-bit substitution in WAV audio samples.
    LsbAudio,
    /// DSSS-based phase encoding across WAV audio segments.
    PhaseEncoding,
    /// Echo-kernel delay modulation in WAV audio (`array_windows`).
    EchoHiding,
    /// Zero-width Unicode character injection at grapheme boundaries.
    ZeroWidthText,
    /// PDF content-stream LSB coefficient modification.
    PdfContentStream,
    /// PDF XMP / document-level metadata field embedding.
    PdfMetadata,
    /// Zero-modification corpus cover selection via ANN search.
    CorpusSelection,
    /// Dual-payload deniable steganography with decoy and real payloads.
    DualPayload,
}

// ─── Platform / Chroma profiles ───────────────────────────────────────────────

/// Chroma subsampling mode used by a target platform's compressor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChromaSubsampling {
    /// 4:2:0 — both Cb and Cr are halved horizontally and vertically.
    Yuv420,
    /// 4:2:2 — Cb and Cr are halved horizontally only.
    Yuv422,
    /// 4:4:4 — full chroma resolution, no subsampling.
    Yuv444,
}

/// Target platform for compression-survivable embedding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PlatformProfile {
    /// Instagram JPEG recompression settings.
    Instagram,
    /// Twitter/X JPEG recompression settings.
    Twitter,
    /// Imgur JPEG recompression settings.
    Imgur,
    /// `WhatsApp` JPEG recompression settings.
    WhatsApp,
    /// Telegram JPEG recompression settings.
    Telegram,
    /// Custom platform with explicit quality and chroma settings.
    Custom {
        /// JPEG quality factor (1–100).
        quality: u8,
        /// Chroma subsampling mode applied by the platform.
        subsampling: ChromaSubsampling,
    },
}

// ─── EmbeddingProfile ─────────────────────────────────────────────────────────

/// Embedding strategy profile selected at the call site.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EmbeddingProfile {
    /// Default embedding with no detectability constraint.
    Standard,
    /// Adaptive embedding bounded by a detectability budget.
    Adaptive {
        /// Maximum acceptable detectability in decibels.
        max_detectability_db: f64,
    },
    /// Embedding hardened to survive a target platform's recompression.
    CompressionSurvivable {
        /// Target platform whose recompression pipeline must be survived.
        platform: PlatformProfile,
    },
    /// Zero-modification corpus-based cover selection.
    CorpusBased,
}

/// Maximum detectability budget (dB) used when no explicit value is configured.
///
/// Chosen as a conservative threshold that balances stealth and payload
/// capacity.  A negative value means the stego cover must have *lower* spectral
/// energy than the original.
pub const DEFAULT_ADAPTIVE_DETECTABILITY_DB: f64 = -12.0;

impl EmbeddingProfile {
    /// Return the standard adaptive profile with the default detectability
    /// budget ([`DEFAULT_ADAPTIVE_DETECTABILITY_DB`]).
    #[must_use]
    pub const fn default_adaptive() -> Self {
        Self::Adaptive {
            max_detectability_db: DEFAULT_ADAPTIVE_DETECTABILITY_DB,
        }
    }
}

// ─── DistributionPattern ──────────────────────────────────────────────────────

/// How payload shards are distributed across carriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ManyToManyMode {
    /// Each shard is replicated to every carrier.
    Replicate,
    /// Shards are striped across carriers sequentially.
    Stripe,
    /// Shards are distributed diagonally across a carrier matrix.
    Diagonal,
    /// Shards are assigned to carriers at random.
    Random,
}

/// Distribution topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DistributionPattern {
    /// Single payload embedded in a single carrier.
    OneToOne,
    /// Payload split with Reed-Solomon across many carriers.
    OneToMany {
        /// Number of data shards (K).
        data_shards: u8,
        /// Number of parity shards (M).
        parity_shards: u8,
    },
    /// Many independent payloads merged into one carrier.
    ManyToOne,
    /// Many payloads distributed across many carriers.
    ManyToMany {
        /// Strategy for assigning shards to carriers.
        mode: ManyToManyMode,
    },
}

// ─── Shard ────────────────────────────────────────────────────────────────────

/// A single erasure-coded shard of a payload.
///
/// HMAC tag covers `index || total || data`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Shard {
    /// Zero-based index of this shard within the set.
    pub index: u8,
    /// Total number of shards in the set (data + parity).
    pub total: u8,
    /// Raw shard bytes.
    pub data: Vec<u8>,
    /// HMAC-SHA-256 tag covering `index || total || data`.
    pub hmac_tag: [u8; 32],
}

impl std::fmt::Debug for Shard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shard")
            .field("index", &self.index)
            .field("total", &self.total)
            .field("data_len", &self.data.len())
            .field("hmac_tag", &"[redacted]")
            .finish()
    }
}

impl Serialize for Shard {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Shard", 4)?;
        st.serialize_field("index", &self.index)?;
        st.serialize_field("total", &self.total)?;
        st.serialize_field("data", &self.data)?;
        st.serialize_field("hmac_tag", &self.hmac_tag)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for Shard {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct ShardHelper {
            index: u8,
            total: u8,
            data: Vec<u8>,
            hmac_tag: [u8; 32],
        }
        let h = ShardHelper::deserialize(d)?;
        Ok(Self {
            index: h.index,
            total: h.total,
            data: h.data,
            hmac_tag: h.hmac_tag,
        })
    }
}

// ─── KeyPair ──────────────────────────────────────────────────────────────────

/// An asymmetric key pair.
///
/// Secret key is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    /// Serialised public key bytes.
    pub public_key: Vec<u8>,
    /// Serialised secret key bytes (zeroized on drop).
    pub secret_key: Vec<u8>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key_len", &self.public_key.len())
            .field("secret_key", &"[redacted]")
            .finish()
    }
}

// ─── Signature ────────────────────────────────────────────────────────────────

/// A detached digital signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(pub Bytes);

// ─── PqcAlgorithm ─────────────────────────────────────────────────────────────

/// Post-quantum cryptographic algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PqcAlgorithm {
    /// ML-KEM-1024 key encapsulation mechanism (NIST FIPS 203).
    MlKem1024,
    /// ML-DSA-87 digital signature algorithm (NIST FIPS 204).
    MlDsa87,
}

// ─── Capacity ─────────────────────────────────────────────────────────────────

/// Embedding capacity of a cover medium for a given technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    /// Maximum number of payload bytes this cover can hold.
    pub bytes: u64,
    /// The technique used to measure this capacity estimate.
    pub technique: StegoTechnique,
}

impl Capacity {
    /// Returns `true` if this cover can hold the given payload.
    #[must_use]
    pub const fn is_sufficient_for(&self, payload: &Payload) -> bool {
        self.bytes >= payload.len() as u64
    }
}

// ─── DetectabilityRisk ────────────────────────────────────────────────────────

/// Qualitative detectability risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectabilityRisk {
    /// Embedding is statistically indistinguishable from an unmodified cover.
    Low,
    /// Embedding is detectable with specialised tools but not trivially.
    Medium,
    /// Embedding is likely detectable by automated steganalysis.
    High,
}

// ─── AnalysisReport ───────────────────────────────────────────────────────────

/// Spectral-domain detectability metrics comparing an original cover to a
/// stego image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectralScore {
    /// Drop in normalised phase coherence at carrier bins, 0.0–1.0.
    /// 0.0 = no disruption; 1.0 = complete decoherence.
    pub phase_coherence_drop: f64,
    /// Mean SNR drop at carrier bins in dB.  Negative = energy removed
    /// (less detectable); positive = energy added (more detectable).
    pub carrier_snr_drop_db: f64,
    /// Adjacent pixel-pair parity asymmetry, 0.0–1.0.
    /// 0.0 = balanced pairs; higher = LSB bias in cover.
    pub sample_pair_asymmetry: f64,
    /// Qualitative combined risk classification.
    pub combined_risk: DetectabilityRisk,
}

/// Steganalysis report for a cover medium.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// The technique used for this analysis.
    pub technique: StegoTechnique,
    /// Total embedding capacity of the analysed cover.
    pub cover_capacity: Capacity,
    /// Chi-square test score (lower = more uniform = safer).
    pub chi_square_score: f64,
    /// Qualitative detectability risk classification.
    pub detectability_risk: DetectabilityRisk,
    /// Conservative payload size that stays below the detectability threshold.
    pub recommended_max_payload_bytes: u64,
    /// Single-image AI watermark assessment for raster covers.
    pub ai_watermark: Option<AiWatermarkAssessment>,
    /// Spectral-domain score, populated when `spectral_detectability_score`
    /// is called.  `None` when only the basic chi-square analysis was run.
    pub spectral_score: Option<SpectralScore>,
}

/// Single-image AI watermark assessment derived from known generator profiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiWatermarkAssessment {
    /// Whether the cover matched a known AI watermark profile strongly enough.
    pub detected: bool,
    /// Model identifier for the detected watermark, when confidence clears the threshold.
    pub model_id: Option<String>,
    /// Ratio of matched strong carrier bins to total strong carrier bins.
    pub confidence: f64,
    /// Number of strong carrier bins that matched the observed image phases.
    pub matched_strong_bins: usize,
    /// Number of strong carrier bins available in the best matching profile.
    pub total_strong_bins: usize,
}

// ─── WatermarkReceipt ─────────────────────────────────────────────────────────

/// Receipt produced after watermark embedding, for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkReceipt {
    /// Identifier of the recipient this receipt is issued to.
    pub recipient: String,
    /// Name of the watermarking algorithm used.
    pub algorithm: String,
    /// Shard indices that carry this recipient's watermark.
    pub shards: Vec<u8>,
    /// UTC timestamp when the watermark was embedded.
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Display for WatermarkReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "# Watermark Receipt")?;
        writeln!(f, "- **Recipient**: {}", self.recipient)?;
        writeln!(f, "- **Algorithm**: {}", self.algorithm)?;
        writeln!(f, "- **Shards**: {:?}", self.shards)?;
        writeln!(f, "- **Created**: {}", self.created_at)
    }
}

// ─── ArchiveFormat ────────────────────────────────────────────────────────────

/// Archive format for multi-carrier bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchiveFormat {
    /// ZIP archive (DEFLATE compressed).
    Zip,
    /// POSIX TAR archive (uncompressed).
    Tar,
    /// POSIX TAR archive with GZIP compression.
    TarGz,
}

// ─── DeniableKeySet ───────────────────────────────────────────────────────────

/// Two symmetric keys enabling dual-payload deniable steganography.
///
/// Both keys are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeniableKeySet {
    /// Key that decrypts the real payload.
    pub primary_key: Vec<u8>,
    /// Key that decrypts an innocent-looking decoy payload.
    pub decoy_key: Vec<u8>,
}

impl std::fmt::Debug for DeniableKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeniableKeySet")
            .field("primary_key", &"[redacted]")
            .field("decoy_key", &"[redacted]")
            .finish()
    }
}

// ─── DeniablePayloadPair ──────────────────────────────────────────────────────

/// Real and decoy payloads for deniable embedding.
///
/// Both payloads are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeniablePayloadPair {
    /// The genuine secret payload.
    pub real_payload: Vec<u8>,
    /// The innocent-looking decoy payload presented under coercion.
    pub decoy_payload: Vec<u8>,
}

impl std::fmt::Debug for DeniablePayloadPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeniablePayloadPair")
            .field("real_len", &self.real_payload.len())
            .field("decoy_len", &self.decoy_payload.len())
            .finish()
    }
}

// ─── CanaryShard ──────────────────────────────────────────────────────────────

/// A shard planted as a tripwire; access signals distribution compromise.
///
/// Not counted in K for reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryShard {
    /// The underlying shard data.
    pub shard: Shard,
    /// Unique identifier for this canary instance.
    pub canary_id: Uuid,
    /// Optional URL to ping when the canary is accessed.
    pub notify_url: Option<String>,
}

// ─── RetrievalManifest ────────────────────────────────────────────────────────

/// Out-of-band metadata describing where and how to retrieve a dead-drop cover.
///
/// Shared over a separate steganographic channel so the recipient knows
/// which public post to fetch and which technique to extract with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalManifest {
    /// Target platform the cover was posted to.
    pub platform: PlatformProfile,
    /// Public URL where the stego cover can be retrieved.
    pub retrieval_url: String,
    /// Steganographic technique used for embedding.
    pub technique: StegoTechnique,
    /// SHA-256 hex digest of the stego cover bytes (for integrity check).
    pub stego_hash: String,
}

// ─── GeographicManifest ───────────────────────────────────────────────────────

/// Manifest requiring shards to cross jurisdictional boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicManifest {
    /// Entries describing where each shard should reside.
    pub shards: Vec<GeoShardEntry>,
    /// Minimum number of distinct jurisdictions required for reconstruction.
    pub minimum_jurisdictions: u8,
}

/// A single shard entry in a geographic distribution manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoShardEntry {
    /// Zero-based index into the shard set.
    pub shard_index: u8,
    /// ISO 3166-1 alpha-2 or descriptive jurisdiction string.
    pub jurisdiction: String,
    /// Human-readable description of the shard holder (not a name).
    pub holder_description: String,
}

// ─── TimeLockPuzzle ───────────────────────────────────────────────────────────

/// A Rivest sequential-squaring time-lock puzzle wrapping a ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockPuzzle {
    /// Ciphertext that can only be decrypted after solving the puzzle.
    pub ciphertext: Bytes,
    /// RSA modulus `n` used for sequential squaring.
    pub modulus: Vec<u8>,
    /// Starting value `g` for the squaring chain.
    pub start_value: Vec<u8>,
    /// Number of sequential squarings `T` required.
    pub squarings_required: u64,
    /// UTC timestamp when the puzzle was created.
    pub created_at: DateTime<Utc>,
    /// Approximate UTC unlock time (informational, not enforced).
    pub unlock_at: DateTime<Utc>,
}

// ─── SpectralKey ────────────────────────────────────────────────────────

/// Spectral fingerprint key for model-aware corpus indexing.
///
/// Used as a `HashMap` key so all four standard traits are derived.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpectralKey {
    /// Generator model identifier (e.g. `"gemini"`, `"midjourney-v7"`).
    pub model_id: String,
    /// Image resolution `(width, height)` matching this profile.
    pub resolution: (u32, u32),
}

// ─── CorpusEntry ────────────────────────────────────────────────────────

/// An indexed entry in a local image corpus for zero-modification stego.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    /// SHA-256 hash of the source file.
    pub file_hash: [u8; 32],
    /// Path to the file relative to the corpus root.
    pub path: String,
    /// Type of cover medium.
    pub cover_kind: CoverMediaKind,
    /// Precomputed LSB bit pattern for ANN matching.
    pub precomputed_bit_pattern: Bytes,
    /// Optional spectral profile key — set when this is an AI-generated image
    /// identified by [`crate::domain::ports::CoverProfileMatcher`].
    pub spectral_key: Option<SpectralKey>,
}

// ─── StyloProfile ─────────────────────────────────────────────────────────────

/// Configuration for stylometric fingerprint scrubbing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StyloProfile {
    /// Target unique vocabulary size after scrubbing.
    pub target_vocab_size: usize,
    /// Target average sentence length in words.
    pub target_avg_sentence_len: f64,
    /// Whether to normalise punctuation marks to a canonical set.
    pub normalize_punctuation: bool,
}

// ─── PanicWipeConfig ──────────────────────────────────────────────────────────

/// Configuration for emergency secure erasure of all key material.
#[derive(Debug, Clone)]
pub struct PanicWipeConfig {
    /// Paths to key files that must be securely erased.
    pub key_paths: Vec<PathBuf>,
    /// Paths to configuration files containing sensitive data.
    pub config_paths: Vec<PathBuf>,
    /// Temporary directories to wipe recursively.
    pub temp_dirs: Vec<PathBuf>,
}

// ─── WatermarkTripwireTag ─────────────────────────────────────────────────────

/// A per-recipient watermark tag for distribution forgery detection.
///
/// Embedding seed is zeroized on drop.
pub struct WatermarkTripwireTag {
    /// Unique identifier for the recipient this tag tracks.
    pub recipient_id: Uuid,
    /// Secret seed used to derive the watermark bit pattern (zeroized on drop).
    pub embedding_seed: Vec<u8>,
}

impl Zeroize for WatermarkTripwireTag {
    fn zeroize(&mut self) {
        self.embedding_seed.zeroize();
        // recipient_id is not secret; Uuid does not implement Zeroize.
    }
}

impl Drop for WatermarkTripwireTag {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Clone for WatermarkTripwireTag {
    fn clone(&self) -> Self {
        Self {
            recipient_id: self.recipient_id,
            embedding_seed: self.embedding_seed.clone(),
        }
    }
}

impl std::fmt::Debug for WatermarkTripwireTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatermarkTripwireTag")
            .field("recipient_id", &self.recipient_id)
            .field("embedding_seed", &"[redacted]")
            .finish()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn capacity_insufficient_when_payload_exceeds_limit() {
        let cap = Capacity {
            bytes: 10,
            technique: StegoTechnique::LsbImage,
        };
        let large = Payload::from_bytes(vec![0u8; 11]);
        assert!(!cap.is_sufficient_for(&large));
    }

    #[test]
    fn capacity_sufficient_when_payload_fits_exactly() {
        let cap = Capacity {
            bytes: 10,
            technique: StegoTechnique::LsbImage,
        };
        let exact = Payload::from_bytes(vec![0u8; 10]);
        assert!(cap.is_sufficient_for(&exact));
    }

    #[test]
    fn payload_from_str_utf8_round_trips() -> TestResult {
        let p = Payload::from_str_utf8("hello")?;
        assert_eq!(p.as_bytes(), b"hello");
        Ok(())
    }

    #[test]
    fn shard_round_trips_through_serde_json() -> TestResult {
        let original = Shard {
            index: 2,
            total: 5,
            data: vec![1, 2, 3, 4],
            hmac_tag: [0xAB; 32],
        };
        let json = serde_json::to_string(&original)?;
        let decoded: Shard = serde_json::from_str(&json)?;
        assert_eq!(decoded.index, 2);
        assert_eq!(decoded.total, 5);
        assert_eq!(decoded.data, &[1, 2, 3, 4]);
        assert_eq!(decoded.hmac_tag, [0xAB; 32]);
        Ok(())
    }

    #[test]
    fn watermark_receipt_display_contains_heading() -> TestResult {
        let receipt = WatermarkReceipt {
            recipient: "alice".into(),
            algorithm: "lsb".into(),
            shards: vec![0, 1, 2],
            created_at: DateTime::from_timestamp(0, 0).ok_or("invalid timestamp")?,
        };
        let s = receipt.to_string();
        assert!(s.contains("# Watermark Receipt"), "missing heading in: {s}");
        Ok(())
    }

    #[test]
    fn geographic_manifest_serialises_roundtrip() -> TestResult {
        let manifest = GeographicManifest {
            shards: vec![
                GeoShardEntry {
                    shard_index: 0,
                    jurisdiction: "DE".into(),
                    holder_description: "Journalist A".into(),
                },
                GeoShardEntry {
                    shard_index: 1,
                    jurisdiction: "CH".into(),
                    holder_description: "Journalist B".into(),
                },
            ],
            minimum_jurisdictions: 2,
        };
        let json = serde_json::to_string(&manifest)?;
        let decoded: GeographicManifest = serde_json::from_str(&json)?;
        assert_eq!(decoded.minimum_jurisdictions, 2);
        assert_eq!(decoded.shards.len(), 2);
        assert_eq!(
            decoded.shards.first().ok_or("no shards")?.jurisdiction,
            "DE"
        );
        Ok(())
    }

    #[test]
    fn deniable_key_set_both_keys_zeroized_on_explicit_call() {
        let mut ks = DeniableKeySet {
            primary_key: vec![0xFF; 32],
            decoy_key: vec![0xAA; 32],
        };
        ks.zeroize();
        assert!(ks.primary_key.iter().all(|&b| b == 0));
        assert!(ks.decoy_key.iter().all(|&b| b == 0));
    }

    #[test]
    fn watermark_tripwire_tag_seed_zeroized_on_explicit_call() {
        let mut tag = WatermarkTripwireTag {
            recipient_id: Uuid::new_v4(),
            embedding_seed: vec![0xDE; 32],
        };
        tag.zeroize();
        assert!(tag.embedding_seed.iter().all(|&b| b == 0));
    }

    #[test]
    fn distribution_pattern_copy_clone() {
        let p = DistributionPattern::OneToMany {
            data_shards: 3,
            parity_shards: 2,
        };
        let q = p;
        assert_eq!(p, q);
    }

    #[test]
    fn analysis_report_serialises() -> TestResult {
        let report = AnalysisReport {
            technique: StegoTechnique::DctJpeg,
            cover_capacity: Capacity {
                bytes: 1024,
                technique: StegoTechnique::DctJpeg,
            },
            chi_square_score: 0.42,
            detectability_risk: DetectabilityRisk::Low,
            recommended_max_payload_bytes: 512,
            ai_watermark: None,
            spectral_score: None,
        };
        let json = serde_json::to_string(&report)?;
        assert!(json.contains("DctJpeg"));
        assert!(json.contains("Low"));
        Ok(())
    }

    #[test]
    fn payload_debug_redacted() {
        let p = Payload::from_bytes(b"secret".to_vec());
        let dbg = format!("{p:?}");
        assert!(dbg.contains("len"));
        assert!(!dbg.contains("secret"));
    }

    #[test]
    fn payload_empty() {
        let p = Payload::from_bytes(Vec::new());
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn keypair_debug_redacted() {
        let kp = KeyPair {
            public_key: vec![1u8; 32],
            secret_key: vec![2u8; 32],
        };
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("[redacted]"));
        assert!(dbg.contains("public_key_len"));
    }

    #[test]
    fn shard_debug_redacted() {
        let s = Shard {
            index: 0,
            total: 5,
            data: vec![0u8; 100],
            hmac_tag: [0u8; 32],
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("[redacted]"));
        assert!(dbg.contains("data_len"));
    }

    #[test]
    fn deniable_payload_pair_debug_redacted() {
        let pair = DeniablePayloadPair {
            real_payload: vec![1u8; 50],
            decoy_payload: vec![2u8; 30],
        };
        let dbg = format!("{pair:?}");
        assert!(dbg.contains("real_len"));
        assert!(dbg.contains("decoy_len"));
    }

    #[test]
    fn deniable_key_set_debug_redacted() {
        let ks = DeniableKeySet {
            primary_key: vec![1u8; 32],
            decoy_key: vec![2u8; 32],
        };
        let dbg = format!("{ks:?}");
        assert!(dbg.contains("[redacted]"));
        assert!(!dbg.contains("\\x01"));
    }

    #[test]
    fn watermark_tripwire_tag_debug_redacted() {
        let tag = WatermarkTripwireTag {
            recipient_id: Uuid::nil(),
            embedding_seed: vec![0xFF; 16],
        };
        let dbg = format!("{tag:?}");
        assert!(dbg.contains("[redacted]"));
    }

    #[test]
    fn watermark_tripwire_tag_clone() {
        let tag = WatermarkTripwireTag {
            recipient_id: Uuid::new_v4(),
            embedding_seed: vec![0xAA; 32],
        };
        let cloned = tag.clone();
        assert_eq!(tag.recipient_id, cloned.recipient_id);
        assert_eq!(tag.embedding_seed, cloned.embedding_seed);
    }

    #[test]
    fn time_lock_puzzle_serialises() -> TestResult {
        let puzzle = TimeLockPuzzle {
            ciphertext: Bytes::from(vec![1u8; 32]),
            modulus: vec![2u8; 16],
            start_value: vec![3u8; 16],
            squarings_required: 1000,
            created_at: Utc::now(),
            unlock_at: Utc::now(),
        };
        let json = serde_json::to_string(&puzzle)?;
        assert!(json.contains("squarings_required"));
        Ok(())
    }

    #[test]
    fn retrieval_manifest_serialises() -> TestResult {
        let manifest = RetrievalManifest {
            platform: PlatformProfile::Instagram,
            retrieval_url: "https://example.com/post/123".into(),
            technique: StegoTechnique::LsbImage,
            stego_hash: "abcdef123456".into(),
        };
        let json = serde_json::to_string(&manifest)?;
        let decoded: RetrievalManifest = serde_json::from_str(&json)?;
        assert_eq!(decoded.retrieval_url, "https://example.com/post/123");
        Ok(())
    }

    #[test]
    fn corpus_entry_serialises() -> TestResult {
        let entry = CorpusEntry {
            file_hash: [0xAB; 32],
            path: "images/cover.png".into(),
            cover_kind: CoverMediaKind::PngImage,
            precomputed_bit_pattern: Bytes::from(vec![0u8; 16]),
            spectral_key: None,
        };
        let json = serde_json::to_string(&entry)?;
        assert!(json.contains("images/cover.png"));
        Ok(())
    }

    #[test]
    fn stylo_profile_default_values() {
        let profile = StyloProfile {
            target_vocab_size: 500,
            target_avg_sentence_len: 15.0,
            normalize_punctuation: true,
        };
        assert!(profile.normalize_punctuation);
        assert_eq!(profile.target_vocab_size, 500);
    }

    #[test]
    fn archive_format_variants_are_distinct() {
        assert_ne!(ArchiveFormat::Zip, ArchiveFormat::Tar);
        assert_ne!(ArchiveFormat::Tar, ArchiveFormat::TarGz);
        assert_ne!(ArchiveFormat::Zip, ArchiveFormat::TarGz);
    }

    #[test]
    fn canary_shard_serialises() -> TestResult {
        let shard = CanaryShard {
            shard: Shard {
                index: 0,
                total: 3,
                data: vec![1, 2, 3],
                hmac_tag: [0u8; 32],
            },
            canary_id: Uuid::new_v4(),
            notify_url: Some("https://example.com/canary".into()),
        };
        let json = serde_json::to_string(&shard)?;
        assert!(json.contains("canary_id"));
        Ok(())
    }

    #[test]
    fn panic_wipe_config_debug() {
        let config = PanicWipeConfig {
            key_paths: vec![std::path::PathBuf::from("/tmp/key")],
            config_paths: vec![],
            temp_dirs: vec![],
        };
        let dbg = format!("{config:?}");
        assert!(dbg.contains("key_paths"));
    }

    #[test]
    fn spectral_key_round_trips_through_serde_json() -> TestResult {
        let key = SpectralKey {
            model_id: "gemini".to_string(),
            resolution: (1024, 1024),
        };
        let json = serde_json::to_string(&key)?;
        let decoded: SpectralKey = serde_json::from_str(&json)?;
        assert_eq!(decoded.model_id, "gemini");
        assert_eq!(decoded.resolution, (1024, 1024));
        Ok(())
    }

    #[test]
    fn spectral_key_usable_as_hashmap_key() {
        let mut map = std::collections::HashMap::new();
        let key = SpectralKey {
            model_id: "gemini".to_string(),
            resolution: (1024, 1024),
        };
        map.insert(key.clone(), 42usize);
        assert_eq!(map.get(&key), Some(&42));
    }

    #[test]
    fn corpus_entry_with_spectral_key_serialises() -> TestResult {
        let entry = CorpusEntry {
            file_hash: [0xCC; 32],
            path: "ai/image.png".into(),
            cover_kind: CoverMediaKind::PngImage,
            precomputed_bit_pattern: Bytes::from(vec![0u8; 8]),
            spectral_key: Some(SpectralKey {
                model_id: "gemini".to_string(),
                resolution: (1024, 1024),
            }),
        };
        let json = serde_json::to_string(&entry)?;
        assert!(json.contains("gemini"));
        let decoded: CorpusEntry = serde_json::from_str(&json)?;
        assert!(decoded.spectral_key.is_some());
        Ok(())
    }

    #[test]
    fn corpus_entry_without_spectral_key_serialises() -> TestResult {
        let entry = CorpusEntry {
            file_hash: [0xDD; 32],
            path: "camera/photo.jpg".into(),
            cover_kind: CoverMediaKind::JpegImage,
            precomputed_bit_pattern: Bytes::from(vec![0u8; 8]),
            spectral_key: None,
        };
        let json = serde_json::to_string(&entry)?;
        let decoded: CorpusEntry = serde_json::from_str(&json)?;
        assert!(decoded.spectral_key.is_none());
        Ok(())
    }

    #[test]
    fn default_adaptive_uses_named_constant() {
        // The default adaptive profile must encode the canonical threshold so
        // the runner never hard-codes a magic number.
        let profile = EmbeddingProfile::default_adaptive();
        assert!(matches!(
            profile,
            EmbeddingProfile::Adaptive {
                max_detectability_db
            } if (max_detectability_db - DEFAULT_ADAPTIVE_DETECTABILITY_DB).abs() < f64::EPSILON
        ));
    }
}
