//! Port trait definitions for all bounded contexts.
//!
//! Each trait defines a capability boundary between the domain and its
//! adapters. All traits are **object-safe** — verified by compile-time
//! assertions below. No I/O, no `async`, no concrete types from external
//! crates appear in return positions.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::errors::{
    AdaptiveError, AnalysisError, ArchiveError, CanaryError, CorrectionError, CryptoError,
    DeadDropError, DeniableError, DistributionError, MediaError, OpsecError, PdfError,
    ReconstructionError, ScrubberError, StegoError, TimeLockError,
};
use crate::domain::types::{
    AnalysisReport, ArchiveFormat, CanaryShard, Capacity, CoverMedia, DeniableKeySet,
    DeniablePayloadPair, EmbeddingProfile, GeographicManifest, KeyPair, Payload, PlatformProfile,
    Shard, Signature, StegoTechnique, StyloProfile, TimeLockPuzzle, WatermarkReceipt,
    WatermarkTripwireTag,
};

// ─── Crypto ───────────────────────────────────────────────────────────────────

/// Key encapsulation mechanism (KEM) port — ML-KEM-1024.
///
/// All operations are constant-time with respect to secret key material.
pub trait Encryptor {
    /// Generate a fresh key pair.
    ///
    /// # Errors
    /// Returns [`CryptoError::KeyGenFailed`] if the RNG or parameter
    /// validation fails.
    fn generate_keypair(&self) -> Result<KeyPair, CryptoError>;

    /// Encapsulate a shared secret using the recipient's public key.
    ///
    /// Returns `(ciphertext, shared_secret)`.
    ///
    /// # Errors
    /// Returns [`CryptoError::EncapsulationFailed`] on invalid key material.
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Bytes, Bytes), CryptoError>;

    /// Decapsulate a shared secret using the holder's secret key.
    ///
    /// # Errors
    /// Returns [`CryptoError::DecapsulationFailed`] on invalid key or
    /// ciphertext.
    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Bytes, CryptoError>;
}

/// Digital signature port — ML-DSA-87.
///
/// All comparisons over signature bytes use constant-time equality.
pub trait Signer {
    /// Generate a fresh signing key pair.
    ///
    /// # Errors
    /// Returns [`CryptoError::KeyGenFailed`] if key generation fails.
    fn generate_keypair(&self) -> Result<KeyPair, CryptoError>;

    /// Sign a message with the secret signing key.
    ///
    /// # Errors
    /// Returns [`CryptoError::SigningFailed`] on invalid key material.
    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Signature, CryptoError>;

    /// Verify a signature against the public key and message.
    ///
    /// Returns `true` when the signature is valid.
    ///
    /// # Errors
    /// Returns [`CryptoError::VerificationFailed`] only on implementation
    /// errors; an invalid signature returns `Ok(false)`.
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, CryptoError>;
}

/// Symmetric cipher port — AES-256-GCM.
pub trait SymmetricCipher {
    /// Encrypt `plaintext` with `key` and `nonce`.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKeyLength`] or
    /// [`CryptoError::EncryptionFailed`].
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Bytes, CryptoError>;

    /// Decrypt and authenticate `ciphertext` with `key` and `nonce`.
    ///
    /// # Errors
    /// Returns [`CryptoError::DecryptionFailed`] if authentication fails.
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Bytes, CryptoError>;
}

// ─── Error Correction ─────────────────────────────────────────────────────────

/// Reed-Solomon K-of-N erasure coding port.
pub trait ErrorCorrector {
    /// Encode `data` into `data_shards + parity_shards` [`Shard`]s.
    ///
    /// Each shard carries an HMAC-SHA-256 tag over `index || total || data`.
    ///
    /// # Errors
    /// Returns [`CorrectionError::InvalidParameters`] or
    /// [`CorrectionError::ReedSolomonError`].
    fn encode(
        &self,
        data: &[u8],
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Vec<Shard>, CorrectionError>;

    /// Decode `shards` back to the original bytes.
    ///
    /// Accepts partial shard sets (some may be `None`); requires at least
    /// `data_shards` valid shards with passing HMAC tags.
    ///
    /// # Errors
    /// Returns [`CorrectionError::InsufficientShards`],
    /// [`CorrectionError::HmacMismatch`], or
    /// [`CorrectionError::ReedSolomonError`].
    fn decode(
        &self,
        shards: &[Option<Shard>],
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Bytes, CorrectionError>;
}

// ─── Steganography ────────────────────────────────────────────────────────────

/// Embedding half of a steganographic technique.
pub trait EmbedTechnique {
    /// The technique identifier for this implementation.
    fn technique(&self) -> StegoTechnique;

    /// Estimate how many payload bytes `cover` can hold.
    ///
    /// # Errors
    /// Returns [`StegoError::UnsupportedCoverType`] if the cover kind is
    /// incompatible with this technique.
    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError>;

    /// Embed `payload` into `cover`, returning the stego cover.
    ///
    /// # Errors
    /// Returns [`StegoError::PayloadTooLarge`] or
    /// [`StegoError::MalformedCoverData`].
    fn embed(&self, cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError>;
}

/// Extraction half of a steganographic technique.
pub trait ExtractTechnique {
    /// The technique identifier for this implementation.
    fn technique(&self) -> StegoTechnique;

    /// Extract a hidden payload from `stego`.
    ///
    /// # Errors
    /// Returns [`StegoError::NoPayloadFound`] or
    /// [`StegoError::IntegrityCheckFailed`].
    fn extract(&self, stego: &CoverMedia) -> Result<Payload, StegoError>;
}

// ─── Media ────────────────────────────────────────────────────────────────────

/// Codec adapter port for loading and saving cover media files.
///
/// I/O is performed by the adapter; the domain receives decoded pixels/samples.
pub trait MediaLoader {
    /// Load a media file from `path` and return decoded [`CoverMedia`].
    ///
    /// # Errors
    /// Returns [`MediaError::UnsupportedFormat`], [`MediaError::DecodeFailed`],
    /// or [`MediaError::IoError`].
    fn load(&self, path: &Path) -> Result<CoverMedia, MediaError>;

    /// Encode `media` and write it to `path`.
    ///
    /// # Errors
    /// Returns [`MediaError::EncodeFailed`] or [`MediaError::IoError`].
    fn save(&self, media: &CoverMedia, path: &Path) -> Result<(), MediaError>;
}

// ─── PDF ──────────────────────────────────────────────────────────────────────

/// First-class PDF bounded context port.
///
/// Covers parsing, page rendering, content-stream LSB, and metadata embedding.
pub trait PdfProcessor {
    /// Parse a PDF file from `path` into a [`CoverMedia`].
    ///
    /// # Errors
    /// Returns [`PdfError::ParseFailed`] or [`PdfError::IoError`].
    fn load_pdf(&self, path: &Path) -> Result<CoverMedia, PdfError>;

    /// Serialise `media` back to a PDF file at `path`.
    ///
    /// # Errors
    /// Returns [`PdfError::RebuildFailed`] or [`PdfError::IoError`].
    fn save_pdf(&self, media: &CoverMedia, path: &Path) -> Result<(), PdfError>;

    /// Rasterise every page of `pdf` to a PNG [`CoverMedia`].
    ///
    /// # Errors
    /// Returns [`PdfError::RenderFailed`] on any page failure.
    fn render_pages_to_images(&self, pdf: &CoverMedia) -> Result<Vec<CoverMedia>, PdfError>;

    /// Reconstruct a PDF from rasterised `images`, retaining `original`
    /// metadata where possible.
    ///
    /// # Errors
    /// Returns [`PdfError::RebuildFailed`].
    fn rebuild_pdf_from_images(
        &self,
        images: Vec<CoverMedia>,
        original: &CoverMedia,
    ) -> Result<CoverMedia, PdfError>;

    /// Embed `payload` via content-stream LSB coefficient modification.
    ///
    /// # Errors
    /// Returns [`PdfError::EmbedFailed`].
    fn embed_in_content_stream(
        &self,
        pdf: CoverMedia,
        payload: &Payload,
    ) -> Result<CoverMedia, PdfError>;

    /// Extract a payload previously embedded in the content stream.
    ///
    /// # Errors
    /// Returns [`PdfError::ExtractFailed`].
    fn extract_from_content_stream(&self, pdf: &CoverMedia) -> Result<Payload, PdfError>;

    /// Embed `payload` into XMP / document-level metadata fields.
    ///
    /// # Errors
    /// Returns [`PdfError::EmbedFailed`].
    fn embed_in_metadata(&self, pdf: CoverMedia, payload: &Payload)
    -> Result<CoverMedia, PdfError>;

    /// Extract a payload previously embedded in XMP / document-level metadata.
    ///
    /// # Errors
    /// Returns [`PdfError::ExtractFailed`].
    fn extract_from_metadata(&self, pdf: &CoverMedia) -> Result<Payload, PdfError>;
}

// ─── Distribution ─────────────────────────────────────────────────────────────

/// Payload distribution port.
///
/// Accepts an embedder trait-object so the distribution pattern is decoupled
/// from any specific steganographic technique.
pub trait Distributor {
    /// Distribute `payload` across `covers` according to `profile`.
    ///
    /// # Errors
    /// Returns [`DistributionError::InsufficientCovers`] or
    /// [`DistributionError::EmbedFailed`].
    fn distribute(
        &self,
        payload: &Payload,
        profile: &EmbeddingProfile,
        covers: Vec<CoverMedia>,
        embedder: &dyn EmbedTechnique,
    ) -> Result<Vec<CoverMedia>, DistributionError>;
}

// ─── Reconstruction ───────────────────────────────────────────────────────────

/// K-of-N shard reconstruction port.
pub trait Reconstructor {
    /// Reconstruct the original payload from stego `covers`.
    ///
    /// `progress_cb` is called with `(completed, total)` after each
    /// extraction step so callers can display progress.
    ///
    /// # Errors
    /// Returns [`ReconstructionError::InsufficientCovers`],
    /// [`ReconstructionError::ExtractionFailed`], or
    /// [`ReconstructionError::CorrectionFailed`].
    fn reconstruct(
        &self,
        covers: Vec<CoverMedia>,
        extractor: &dyn ExtractTechnique,
        progress_cb: &dyn Fn(usize, usize),
    ) -> Result<Payload, ReconstructionError>;
}

// ─── Analysis ─────────────────────────────────────────────────────────────────

/// Steganalysis and capacity estimation port.
pub trait CapacityAnalyser {
    /// Analyse `cover` with `technique` and return an [`AnalysisReport`].
    ///
    /// # Errors
    /// Returns [`AnalysisError::UnsupportedCoverType`] or
    /// [`AnalysisError::ComputationFailed`].
    fn analyse(
        &self,
        cover: &CoverMedia,
        technique: StegoTechnique,
    ) -> Result<AnalysisReport, AnalysisError>;
}

// ─── Archive ──────────────────────────────────────────────────────────────────

/// Multi-carrier archive port (ZIP / TAR / TAR.GZ).
pub trait ArchiveHandler {
    /// Pack `files` (name, bytes) into an archive of `format`.
    ///
    /// # Errors
    /// Returns [`ArchiveError::PackFailed`] or
    /// [`ArchiveError::UnsupportedFormat`].
    fn pack(&self, files: &[(&str, &[u8])], format: ArchiveFormat) -> Result<Bytes, ArchiveError>;

    /// Unpack `archive` of `format` into `(name, bytes)` pairs.
    ///
    /// # Errors
    /// Returns [`ArchiveError::UnpackFailed`] or
    /// [`ArchiveError::UnsupportedFormat`].
    fn unpack(
        &self,
        archive: &[u8],
        format: ArchiveFormat,
    ) -> Result<Vec<(String, Bytes)>, ArchiveError>;
}

// ─── Adaptive Embedding ───────────────────────────────────────────────────────

/// Camera-model statistical fingerprint — used to defeat model-based
/// steganalysis by matching the cover's noise floor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraProfile {
    /// JPEG quantisation table (64 coefficients in zig-zag order).
    pub quantisation_table: Vec<u16>,
    /// Estimated noise floor of the camera sensor (in decibels).
    pub noise_floor_db: f64,
    /// Human-readable camera model identifier.
    pub model_id: String,
}

/// Spectral fingerprint for a single AI image generator model.
///
/// Stores per-resolution carrier frequency maps extracted from reference
/// images (pure-black / pure-white outputs dominated by the watermark
/// signal).  The `carrier_map` key is `"WIDTHxHEIGHT"` (e.g. `"1024x1024"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiGenProfile {
    /// Generator identifier, e.g. `"gemini"`, `"midjourney-v7"`.
    pub model_id: String,
    /// Per-channel embedding weights `[R, G, B]` (G is reference=1.0).
    pub channel_weights: [f64; 3],
    /// Map from `"WxH"` resolution string to carrier bin list.
    pub carrier_map: HashMap<String, Vec<CarrierBin>>,
}

impl AiGenProfile {
    /// Return carrier bins for the given resolution, or `None` if unknown.
    #[must_use]
    pub fn carrier_bins_for(&self, width: u32, height: u32) -> Option<&[CarrierBin]> {
        let key = format!("{width}x{height}");
        self.carrier_map.get(&key).map(Vec::as_slice)
    }
}

/// A single frequency-domain carrier bin occupied by an AI generator's
/// watermark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrierBin {
    /// `(row_bin, col_bin)` in the 2-D FFT of the green channel.
    pub freq: (u32, u32),
    /// Expected phase angle of the carrier (radians).
    pub phase: f64,
    /// Measured phase coherence across reference images, clamped to
    /// `0.0..=1.0` by the constructor.
    coherence: f64,
}

impl CarrierBin {
    /// Construct a `CarrierBin`, clamping `coherence` to `0.0..=1.0`.
    #[must_use]
    pub const fn new(freq: (u32, u32), phase: f64, coherence: f64) -> Self {
        Self {
            freq,
            phase,
            coherence: coherence.clamp(0.0, 1.0),
        }
    }

    /// Return the (clamped) phase coherence value.
    #[must_use]
    pub const fn coherence(&self) -> f64 {
        self.coherence
    }

    /// Return `true` when coherence ≥ 0.90 — a reliable carrier.
    #[must_use]
    pub fn is_strong(&self) -> bool {
        self.coherence >= 0.90
    }
}

/// Discriminated union of cover-source fingerprint profiles.
///
/// Use `CoverProfile::Camera` for traditional camera-sourced images and
/// `CoverProfile::AiGenerator` for AI-generated covers (Gemini, Midjourney,
/// etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum CoverProfile {
    /// Traditional camera-sourced image (JPEG quant table + sensor noise).
    Camera(CameraProfile),
    /// AI-generated image with per-resolution spectral carrier bins.
    AiGenerator(AiGenProfile),
}

impl CoverProfile {
    /// Return the human-readable generator / camera model identifier.
    #[must_use]
    pub fn model_id(&self) -> &str {
        match self {
            Self::Camera(p) => &p.model_id,
            Self::AiGenerator(p) => &p.model_id,
        }
    }
}

/// Adversarial embedding optimiser port (STC-inspired).
///
/// Reorders bit assignments after embedding to minimise chi-square distance
/// from the unmodified cover's statistical distribution.
pub trait AdaptiveOptimiser {
    /// Optimise `stego` to stay within `target_db` of the original's
    /// statistical distribution.
    ///
    /// # Errors
    /// Returns [`AdaptiveError::BudgetNotMet`] if no permutation achieves
    /// the target.
    fn optimise(
        &self,
        stego: CoverMedia,
        original: &CoverMedia,
        target_db: f64,
    ) -> Result<CoverMedia, AdaptiveError>;
}

/// Cover profile matching port — detects whether a cover is AI-generated or
/// camera-sourced.
pub trait CoverProfileMatcher {
    /// Return the best-matching [`CoverProfile`] for `cover`, or `None`
    /// if no profile is close enough.
    fn profile_for(&self, cover: &CoverMedia) -> Option<CoverProfile>;

    /// Apply `profile` to `cover` (e.g. adjust JPEG quant tables for a
    /// camera profile; no-op for AI profiles — we avoid their bins instead).
    ///
    /// # Errors
    /// Returns [`AdaptiveError::ProfileMatchFailed`].
    fn apply_profile(
        &self,
        cover: CoverMedia,
        profile: &CoverProfile,
    ) -> Result<CoverMedia, AdaptiveError>;
}

/// Compression survivability port — social media platform recompression.
pub trait CompressionSimulator {
    /// Simulate a target platform's recompression pipeline on `cover`.
    ///
    /// # Errors
    /// Returns [`AdaptiveError::CompressionSimFailed`].
    fn simulate(
        &self,
        cover: CoverMedia,
        platform: &PlatformProfile,
    ) -> Result<CoverMedia, AdaptiveError>;

    /// Estimate the embedding capacity that survives `platform`'s pipeline.
    ///
    /// # Errors
    /// Returns [`AdaptiveError::CompressionSimFailed`].
    fn survivable_capacity(
        &self,
        cover: &CoverMedia,
        platform: &PlatformProfile,
    ) -> Result<Capacity, AdaptiveError>;
}

// ─── Deniable Steganography ───────────────────────────────────────────────────

/// Dual-payload deniable steganography port.
///
/// The stego cover is indistinguishable regardless of which key is presented.
pub trait DeniableEmbedder {
    /// Embed both the real and decoy payload in `cover`.
    ///
    /// The resulting cover decrypts to `pair.real_payload` under
    /// `keys.primary_key` and to `pair.decoy_payload` under `keys.decoy_key`.
    ///
    /// # Errors
    /// Returns [`DeniableError::InsufficientCapacity`] or
    /// [`DeniableError::EmbedFailed`].
    fn embed_dual(
        &self,
        cover: CoverMedia,
        pair: &DeniablePayloadPair,
        keys: &DeniableKeySet,
        embedder: &dyn EmbedTechnique,
    ) -> Result<CoverMedia, DeniableError>;

    /// Extract a payload from `stego` using the provided `key`.
    ///
    /// Returns the decoy payload when given the decoy key, and the real
    /// payload when given the primary key — neither party can prove which.
    ///
    /// # Errors
    /// Returns [`DeniableError::ExtractionFailed`].
    fn extract_with_key(
        &self,
        stego: &CoverMedia,
        key: &[u8],
        extractor: &dyn ExtractTechnique,
    ) -> Result<Payload, DeniableError>;
}

// ─── Operational Security ─────────────────────────────────────────────────────

/// Emergency panic-wipe port.
///
/// Synchronous and best-effort: logs failures internally but completes all
/// wipe steps regardless. Must never propagate an error to the caller under
/// duress.
pub trait PanicWiper {
    /// Securely erase all paths described in `config`.
    ///
    /// # Errors
    /// Returns [`OpsecError::WipeStepFailed`] only when *all* steps have
    /// been attempted and logging is safe. Under duress this should be
    /// treated as non-fatal by the caller.
    fn wipe(&self, config: &crate::domain::types::PanicWipeConfig) -> Result<(), OpsecError>;
}

/// Forensic watermark tripwire port.
///
/// Unique per-recipient watermarks allow identifying which copy of a
/// distributed set was leaked.
pub trait ForensicWatermarker {
    /// Embed a per-recipient tripwire watermark into `cover`.
    ///
    /// # Errors
    /// Returns [`OpsecError::WatermarkError`].
    fn embed_tripwire(
        &self,
        cover: CoverMedia,
        tag: &WatermarkTripwireTag,
    ) -> Result<CoverMedia, OpsecError>;

    /// Identify which recipient's watermark is present in `stego`.
    ///
    /// Returns the matching [`WatermarkTripwireTag`] from `tags`, or `None`
    /// if no match is found.
    ///
    /// # Errors
    /// Returns [`OpsecError::WatermarkError`] on implementation error.
    fn identify_recipient(
        &self,
        stego: &CoverMedia,
        tags: &[WatermarkTripwireTag],
    ) -> Result<Option<WatermarkReceipt>, OpsecError>;
}

/// Amnesiac in-memory pipeline port.
///
/// The entire embed/extract cycle runs without touching the filesystem.
/// Uses [`std::io::pipe`] (stable 1.87) internally.
pub trait AmnesiaPipeline {
    /// Embed a payload read from `cover_input` and `payload_input` using
    /// `technique`, writing the stego output to `output`.
    ///
    /// No temporary files, logs of sensitive data, or crash dumps are created.
    ///
    /// # Errors
    /// Returns [`OpsecError::PipelineError`].
    fn embed_in_memory(
        &self,
        payload_input: &mut dyn Read,
        cover_input: &mut dyn Read,
        output: &mut dyn Write,
        technique: &dyn EmbedTechnique,
    ) -> Result<(), OpsecError>;
}

/// Geographic threshold distribution port.
///
/// Annotates shards with jurisdictional metadata, producing a
/// [`GeographicManifest`] that makes legal compulsion across jurisdictions
/// impractical.
pub trait GeographicDistributor {
    /// Distribute `payload` across `covers` and annotate each shard with
    /// jurisdictional metadata from `manifest`.
    ///
    /// # Errors
    /// Returns [`OpsecError::ManifestError`].
    fn distribute_with_manifest(
        &self,
        payload: &Payload,
        covers: Vec<CoverMedia>,
        manifest: &GeographicManifest,
        embedder: &dyn EmbedTechnique,
    ) -> Result<Vec<CoverMedia>, OpsecError>;
}

// ─── Canary Shards ────────────────────────────────────────────────────────────

/// Canary shard tripwire port.
pub trait CanaryService {
    /// Embed an additional canary shard in `covers` alongside the regular
    /// distribution.
    ///
    /// Returns the modified covers and the [`CanaryShard`] to be planted in
    /// a honeypot location.
    ///
    /// # Errors
    /// Returns [`CanaryError::NoCovers`] or [`CanaryError::EmbedFailed`].
    fn embed_canary(
        &self,
        covers: Vec<CoverMedia>,
        embedder: &dyn EmbedTechnique,
    ) -> Result<(Vec<CoverMedia>, CanaryShard), CanaryError>;

    /// Return `true` if the `shard`'s notify URL is reachable, indicating
    /// the canary has been accessed.
    ///
    /// Non-blocking check; returns `false` on network error.
    fn check_canary(&self, shard: &CanaryShard) -> bool;
}

// ─── Dead Drop ────────────────────────────────────────────────────────────────

/// Platform-aware dead drop encoder port.
///
/// Produces a stego cover optimised for posting publicly on a target
/// platform. No direct file transfer between parties.
pub trait DeadDropEncoder {
    /// Encode `payload` into `cover` for posting on `platform`.
    ///
    /// The resulting cover survives the platform's recompression pipeline
    /// and can be retrieved by the recipient via public URL.
    ///
    /// # Errors
    /// Returns [`DeadDropError::UnsupportedPlatform`] or
    /// [`DeadDropError::EncodeFailed`].
    fn encode_for_platform(
        &self,
        cover: CoverMedia,
        payload: &Payload,
        platform: &PlatformProfile,
        embedder: &dyn EmbedTechnique,
    ) -> Result<CoverMedia, DeadDropError>;
}

// ─── Time-Lock ────────────────────────────────────────────────────────────────

/// Rivest sequential-squaring time-lock puzzle port.
///
/// A payload cannot be decrypted before a specified time, even under
/// compulsion.
pub trait TimeLockService {
    /// Wrap `payload` in a time-lock puzzle that cannot be solved before
    /// `unlock_at`.
    ///
    /// # Errors
    /// Returns [`TimeLockError::ComputationFailed`].
    fn lock(
        &self,
        payload: &Payload,
        unlock_at: DateTime<Utc>,
    ) -> Result<TimeLockPuzzle, TimeLockError>;

    /// Solve the `puzzle` by sequential squaring and decrypt the payload.
    ///
    /// Blocks until the puzzle is solved; may take significant time.
    ///
    /// # Errors
    /// Returns [`TimeLockError::ComputationFailed`] or
    /// [`TimeLockError::DecryptFailed`].
    fn unlock(&self, puzzle: &TimeLockPuzzle) -> Result<Payload, TimeLockError>;

    /// Non-blocking puzzle check. Returns `Ok(Some(payload))` if the puzzle
    /// is already solved, `Ok(None)` if it cannot yet be solved, or an error
    /// if the computation itself fails.
    ///
    /// # Errors
    /// Returns [`TimeLockError::ComputationFailed`] or
    /// [`TimeLockError::DecryptFailed`].
    fn try_unlock(&self, puzzle: &TimeLockPuzzle) -> Result<Option<Payload>, TimeLockError>;
}

// ─── Stylometric Scrubber ─────────────────────────────────────────────────────

/// Linguistic stylometric fingerprint scrubbing port.
///
/// Normalises text to destroy authorship attribution fingerprints without
/// changing the semantic content.
pub trait StyloScrubber {
    /// Scrub `text` to match `profile`.
    ///
    /// # Errors
    /// Returns [`ScrubberError::InvalidUtf8`] or
    /// [`ScrubberError::ProfileNotSatisfied`].
    fn scrub(&self, text: &str, profile: &StyloProfile) -> Result<String, ScrubberError>;
}

// ─── Corpus Steganography ─────────────────────────────────────────────────────

/// Corpus index and zero-modification cover selection port.
pub trait CorpusIndex {
    /// Search the index for covers whose natural bit pattern already encodes
    /// (or closely encodes) `payload` using `technique`.
    ///
    /// Returns up to `max_results` entries sorted by match quality.
    ///
    /// # Errors
    /// Returns [`crate::domain::errors::CorpusError::NoSuitableCover`] or
    /// [`crate::domain::errors::CorpusError::IndexError`].
    fn search(
        &self,
        payload: &Payload,
        technique: StegoTechnique,
        max_results: usize,
    ) -> Result<Vec<crate::domain::types::CorpusEntry>, crate::domain::errors::CorpusError>;

    /// Add the file at `path` to the index, computing its bit-pattern
    /// fingerprint.
    ///
    /// # Errors
    /// Returns [`crate::domain::errors::CorpusError::AddFailed`].
    fn add_to_index(
        &self,
        path: &Path,
    ) -> Result<crate::domain::types::CorpusEntry, crate::domain::errors::CorpusError>;

    /// Scan `corpus_dir` recursively and build the full index.
    ///
    /// Returns the number of entries indexed.
    ///
    /// # Errors
    /// Returns [`crate::domain::errors::CorpusError::IndexError`].
    fn build_index(&self, corpus_dir: &Path) -> Result<usize, crate::domain::errors::CorpusError>;

    /// Search the index for covers that match `payload` and have a
    /// `spectral_key` whose `model_id` and `resolution` match the supplied
    /// values.
    ///
    /// Returns up to `max_results` entries sorted by match quality.
    ///
    /// # Errors
    /// Returns [`crate::domain::errors::CorpusError::NoSuitableCover`] or
    /// [`crate::domain::errors::CorpusError::IndexError`].
    fn search_for_model(
        &self,
        payload: &Payload,
        model_id: &str,
        resolution: (u32, u32),
        max_results: usize,
    ) -> Result<Vec<crate::domain::types::CorpusEntry>, crate::domain::errors::CorpusError>;

    /// Return a sorted list of `(SpectralKey, count)` pairs describing how
    /// many corpus entries are indexed per model/resolution combination.
    ///
    /// Using `Vec` instead of `HashMap` to keep the trait object-safe.
    fn model_stats(&self) -> Vec<(crate::domain::types::SpectralKey, usize)>;
}

// ─── Object-Safety Assertions ─────────────────────────────────────────────────
//
// These compile-time checks verify that every port trait is object-safe.
// If any trait is accidentally made non-object-safe (e.g. by adding a
// method with a generic parameter), this module will fail to compile with
// a clear error pointing at the offending trait.

#[cfg(test)]
mod object_safety_tests {
    use super::*;

    /// Verifies object safety of all port traits.
    #[test]
    fn all_port_traits_are_object_safe() {
        fn assert_object_safe<T: ?Sized>() {}

        assert_object_safe::<dyn Encryptor>();
        assert_object_safe::<dyn Signer>();
        assert_object_safe::<dyn SymmetricCipher>();
        assert_object_safe::<dyn ErrorCorrector>();
        assert_object_safe::<dyn EmbedTechnique>();
        assert_object_safe::<dyn ExtractTechnique>();
        assert_object_safe::<dyn MediaLoader>();
        assert_object_safe::<dyn PdfProcessor>();
        assert_object_safe::<dyn Distributor>();
        assert_object_safe::<dyn Reconstructor>();
        assert_object_safe::<dyn CapacityAnalyser>();
        assert_object_safe::<dyn ArchiveHandler>();
        assert_object_safe::<dyn AdaptiveOptimiser>();
        assert_object_safe::<dyn CoverProfileMatcher>();
        assert_object_safe::<dyn CompressionSimulator>();
        assert_object_safe::<dyn DeniableEmbedder>();
        assert_object_safe::<dyn PanicWiper>();
        assert_object_safe::<dyn ForensicWatermarker>();
        assert_object_safe::<dyn AmnesiaPipeline>();
        assert_object_safe::<dyn GeographicDistributor>();
        assert_object_safe::<dyn CanaryService>();
        assert_object_safe::<dyn DeadDropEncoder>();
        assert_object_safe::<dyn TimeLockService>();
        assert_object_safe::<dyn StyloScrubber>();
        assert_object_safe::<dyn CorpusIndex>();
    }
}

#[cfg(test)]
mod cover_profile_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn camera_profile_model_id_via_cover_profile() {
        let profile = CoverProfile::Camera(CameraProfile {
            quantisation_table: vec![0u16; 64],
            noise_floor_db: -80.0,
            model_id: "canon-eos-r6".to_string(),
        });
        assert_eq!(profile.model_id(), "canon-eos-r6");
    }

    #[test]
    fn ai_gen_profile_model_id_via_cover_profile() {
        let profile = CoverProfile::AiGenerator(AiGenProfile {
            model_id: "gemini".to_string(),
            channel_weights: [0.85, 1.0, 0.70],
            carrier_map: HashMap::new(),
        });
        assert_eq!(profile.model_id(), "gemini");
    }

    #[test]
    fn carrier_bin_coherence_clamped_above_one() {
        let bin = CarrierBin::new((9, 9), 0.0, 1.5);
        assert!((bin.coherence() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn carrier_bin_coherence_clamped_below_zero() {
        let bin = CarrierBin::new((9, 9), 0.0, -0.5);
        assert!((bin.coherence() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn carrier_bin_is_strong_at_exactly_0_90() {
        let strong = CarrierBin::new((9, 9), 0.0, 0.90);
        assert!(strong.is_strong());
    }

    #[test]
    fn carrier_bin_not_strong_below_0_90() {
        let weak = CarrierBin::new((9, 9), 0.0, 0.899_999);
        assert!(!weak.is_strong());
    }

    #[test]
    fn ai_gen_profile_carrier_bins_for_known_resolution() {
        let bins = vec![CarrierBin::new((9, 9), 0.0, 1.0)];
        let mut carrier_map = HashMap::new();
        carrier_map.insert("1024x1024".to_string(), bins);
        let profile = AiGenProfile {
            model_id: "gemini".to_string(),
            channel_weights: [0.85, 1.0, 0.70],
            carrier_map,
        };
        assert!(profile.carrier_bins_for(1024, 1024).is_some());
        assert!(profile.carrier_bins_for(512, 512).is_none());
    }

    #[test]
    fn ai_gen_profile_carrier_bins_count() {
        let bins = vec![
            CarrierBin::new((9, 9), 0.0, 1.0),
            CarrierBin::new((5, 5), 0.0, 1.0),
        ];
        let mut carrier_map = HashMap::new();
        carrier_map.insert("1024x1024".to_string(), bins);
        let profile = AiGenProfile {
            model_id: "gemini".to_string(),
            channel_weights: [0.85, 1.0, 0.70],
            carrier_map,
        };
        assert_eq!(
            profile.carrier_bins_for(1024, 1024).map(<[_]>::len),
            Some(2)
        );
    }

    #[test]
    fn cover_profile_round_trips_through_serde_json() -> TestResult {
        let profile = CoverProfile::AiGenerator(AiGenProfile {
            model_id: "gemini".to_string(),
            channel_weights: [0.85, 1.0, 0.70],
            carrier_map: HashMap::new(),
        });
        let json = serde_json::to_string(&profile)?;
        let decoded: CoverProfile = serde_json::from_str(&json)?;
        assert_eq!(decoded.model_id(), "gemini");
        Ok(())
    }

    #[test]
    fn camera_cover_profile_round_trips_through_serde_json() -> TestResult {
        let profile = CoverProfile::Camera(CameraProfile {
            quantisation_table: vec![2u16; 64],
            noise_floor_db: -75.0,
            model_id: "nikon-z9".to_string(),
        });
        let json = serde_json::to_string(&profile)?;
        let decoded: CoverProfile = serde_json::from_str(&json)?;
        assert_eq!(decoded.model_id(), "nikon-z9");
        Ok(())
    }
}
