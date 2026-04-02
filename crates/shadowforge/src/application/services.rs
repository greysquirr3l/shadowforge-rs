//! Application-layer use-case orchestrators.
//!
//! Each service is a thin wrapper that coordinates domain ports.
//! No file I/O or async runtime — callers provide loaded data.

use std::io::{Read, Write};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::domain::errors::{
    AdaptiveError, AnalysisError, ArchiveError, CanaryError, CorpusError, CorrectionError,
    CryptoError, DeadDropError, DeniableError, DistributionError, OpsecError, ReconstructionError,
    ScrubberError, StegoError, TimeLockError,
};
use crate::domain::ports::{
    AmnesiaPipeline, ArchiveHandler, CanaryService as CanaryServicePort, CapacityAnalyser,
    DeadDropEncoder, DeniableEmbedder, Distributor, EmbedTechnique, Encryptor, ExtractTechnique,
    ForensicWatermarker, PanicWiper, Reconstructor, Signer, StyloScrubber,
    TimeLockService as TimeLockServicePort,
};
use crate::domain::types::{
    AnalysisReport, ArchiveFormat, CanaryShard, CoverMedia, DeniableKeySet, DeniablePayloadPair,
    EmbeddingProfile, KeyPair, PanicWipeConfig, Payload, PlatformProfile, Signature,
    StegoTechnique, StyloProfile, TimeLockPuzzle, WatermarkReceipt, WatermarkTripwireTag,
};

// ─── AppError ─────────────────────────────────────────────────────────────────

/// Unified application error wrapping all domain errors.
#[derive(Debug, Error)]
pub enum AppError {
    /// Crypto subsystem error.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// Steganography error.
    #[error("stego: {0}")]
    Stego(#[from] StegoError),
    /// Distribution error.
    #[error("distribution: {0}")]
    Distribution(#[from] DistributionError),
    /// Reconstruction error.
    #[error("reconstruction: {0}")]
    Reconstruction(#[from] ReconstructionError),
    /// Error-correction error.
    #[error("correction: {0}")]
    Correction(#[from] CorrectionError),
    /// Analysis error.
    #[error("analysis: {0}")]
    Analysis(#[from] AnalysisError),
    /// Archive error.
    #[error("archive: {0}")]
    Archive(#[from] ArchiveError),
    /// Operational security error.
    #[error("opsec: {0}")]
    Opsec(#[from] OpsecError),
    /// Scrubber error.
    #[error("scrubber: {0}")]
    Scrubber(#[from] ScrubberError),
    /// Adaptive embedding error.
    #[error("adaptive: {0}")]
    Adaptive(#[from] AdaptiveError),
    /// Deniable steganography error.
    #[error("deniable: {0}")]
    Deniable(#[from] DeniableError),
    /// Canary shard error.
    #[error("canary: {0}")]
    Canary(#[from] CanaryError),
    /// Dead drop error.
    #[error("dead-drop: {0}")]
    DeadDrop(#[from] DeadDropError),
    /// Time-lock puzzle error.
    #[error("time-lock: {0}")]
    TimeLock(#[from] TimeLockError),
    /// Corpus selection error.
    #[error("corpus: {0}")]
    Corpus(#[from] CorpusError),
}

// ─── EmbedService ─────────────────────────────────────────────────────────────

/// Embeds a payload into a cover medium.
pub struct EmbedService;

impl EmbedService {
    /// Embed `payload` into `cover` using the provided embedder.
    ///
    /// # Errors
    /// Returns [`AppError::Stego`] on embedding failure.
    pub fn embed(
        cover: CoverMedia,
        payload: &Payload,
        embedder: &dyn EmbedTechnique,
    ) -> Result<CoverMedia, AppError> {
        Ok(embedder.embed(cover, payload)?)
    }
}

// ─── ExtractService ───────────────────────────────────────────────────────────

/// Extracts a hidden payload from a stego cover.
pub struct ExtractService;

impl ExtractService {
    /// Extract payload from `stego`.
    ///
    /// # Errors
    /// Returns [`AppError::Stego`] on extraction failure.
    pub fn extract(
        stego: &CoverMedia,
        extractor: &dyn ExtractTechnique,
    ) -> Result<Payload, AppError> {
        Ok(extractor.extract(stego)?)
    }
}

// ─── KeyGenService ────────────────────────────────────────────────────────────

/// Key-pair generation orchestrator.
pub struct KeyGenService;

impl KeyGenService {
    /// Generate a fresh KEM key pair.
    ///
    /// # Errors
    /// Returns [`AppError::Crypto`] on key-generation failure.
    pub fn generate_keypair(encryptor: &dyn Encryptor) -> Result<KeyPair, AppError> {
        Ok(encryptor.generate_keypair()?)
    }

    /// Generate a signing key pair.
    ///
    /// # Errors
    /// Returns [`AppError::Crypto`] on key-generation failure.
    pub fn generate_signing_keypair(signer: &dyn Signer) -> Result<KeyPair, AppError> {
        Ok(signer.generate_keypair()?)
    }

    /// Sign a message.
    ///
    /// # Errors
    /// Returns [`AppError::Crypto`] on signing failure.
    pub fn sign(
        signer: &dyn Signer,
        secret_key: &[u8],
        message: &[u8],
    ) -> Result<Signature, AppError> {
        Ok(signer.sign(secret_key, message)?)
    }

    /// Verify a signature.
    ///
    /// # Errors
    /// Returns [`AppError::Crypto`] on verification failure.
    pub fn verify(
        signer: &dyn Signer,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, AppError> {
        Ok(signer.verify(public_key, message, signature)?)
    }
}

// ─── DistributeService ────────────────────────────────────────────────────────

/// Distribute a payload across multiple covers.
pub struct DistributeService;

impl DistributeService {
    /// Distribute `payload` across `covers`.
    ///
    /// # Errors
    /// Returns [`AppError::Distribution`] on failure.
    pub fn distribute(
        payload: &Payload,
        covers: Vec<CoverMedia>,
        profile: &EmbeddingProfile,
        distributor: &dyn Distributor,
        embedder: &dyn EmbedTechnique,
    ) -> Result<Vec<CoverMedia>, AppError> {
        Ok(distributor.distribute(payload, profile, covers, embedder)?)
    }
}

// ─── ReconstructService ───────────────────────────────────────────────────────

/// Reconstruct a payload from distributed stego covers.
pub struct ReconstructService;

impl ReconstructService {
    /// Reconstruct payload from stego covers.
    ///
    /// # Errors
    /// Returns [`AppError::Reconstruction`] on failure.
    pub fn reconstruct(
        stego_covers: Vec<CoverMedia>,
        extractor: &dyn ExtractTechnique,
        reconstructor: &dyn Reconstructor,
        progress_cb: &dyn Fn(usize, usize),
    ) -> Result<Payload, AppError> {
        Ok(reconstructor.reconstruct(stego_covers, extractor, progress_cb)?)
    }
}

// ─── AnalyseService ───────────────────────────────────────────────────────────

/// Analyse a cover for stego capacity and detectability.
pub struct AnalyseService;

impl AnalyseService {
    /// Analyse `cover` for the given `technique`.
    ///
    /// # Errors
    /// Returns [`AppError::Analysis`] on failure.
    pub fn analyse(
        cover: &CoverMedia,
        technique: StegoTechnique,
        analyser: &dyn CapacityAnalyser,
    ) -> Result<AnalysisReport, AppError> {
        Ok(analyser.analyse(cover, technique)?)
    }
}

// ─── ScrubService ─────────────────────────────────────────────────────────────

/// Scrub text to remove stylometric fingerprints.
pub struct ScrubService;

impl ScrubService {
    /// Scrub text via the provided scrubber port.
    ///
    /// # Errors
    /// Returns [`AppError::Scrubber`] on failure.
    pub fn scrub(
        text: &str,
        profile: &StyloProfile,
        scrubber: &dyn StyloScrubber,
    ) -> Result<String, AppError> {
        Ok(scrubber.scrub(text, profile)?)
    }
}

// ─── ArchiveService ───────────────────────────────────────────────────────────

/// Pack and unpack archive bundles.
pub struct ArchiveService;

impl ArchiveService {
    /// Pack files into an archive.
    ///
    /// # Errors
    /// Returns [`AppError::Archive`] on failure.
    pub fn pack(
        files: &[(&str, &[u8])],
        format: ArchiveFormat,
        handler: &dyn ArchiveHandler,
    ) -> Result<Bytes, AppError> {
        Ok(handler.pack(files, format)?)
    }

    /// Unpack an archive into named files.
    ///
    /// # Errors
    /// Returns [`AppError::Archive`] on failure.
    pub fn unpack(
        archive: &[u8],
        format: ArchiveFormat,
        handler: &dyn ArchiveHandler,
    ) -> Result<Vec<(String, Bytes)>, AppError> {
        Ok(handler.unpack(archive, format)?)
    }
}

// ─── DeniableEmbedService ─────────────────────────────────────────────────────

/// Dual-payload deniable steganography orchestrator.
pub struct DeniableEmbedService;

impl DeniableEmbedService {
    /// Embed both a real and a decoy payload.
    ///
    /// # Errors
    /// Returns [`AppError::Deniable`] on failure.
    pub fn embed_dual(
        cover: CoverMedia,
        pair: &DeniablePayloadPair,
        keys: &DeniableKeySet,
        embedder: &dyn EmbedTechnique,
        deniable: &dyn DeniableEmbedder,
    ) -> Result<CoverMedia, AppError> {
        Ok(deniable.embed_dual(cover, pair, keys, embedder)?)
    }

    /// Extract a payload using the given key.
    ///
    /// # Errors
    /// Returns [`AppError::Deniable`] on failure.
    pub fn extract_with_key(
        stego: &CoverMedia,
        key: &[u8],
        extractor: &dyn ExtractTechnique,
        deniable: &dyn DeniableEmbedder,
    ) -> Result<Payload, AppError> {
        Ok(deniable.extract_with_key(stego, key, extractor)?)
    }
}

// ─── DeadDropService ──────────────────────────────────────────────────────────

/// Platform-aware dead drop orchestrator.
pub struct DeadDropService;

impl DeadDropService {
    /// Encode a payload for posting on a public platform.
    ///
    /// # Errors
    /// Returns [`AppError::DeadDrop`] on failure.
    pub fn encode(
        cover: CoverMedia,
        payload: &Payload,
        platform: &PlatformProfile,
        embedder: &dyn EmbedTechnique,
        encoder: &dyn DeadDropEncoder,
    ) -> Result<CoverMedia, AppError> {
        Ok(encoder.encode_for_platform(cover, payload, platform, embedder)?)
    }
}

// ─── TimeLockServiceApp ───────────────────────────────────────────────────────

/// Time-lock puzzle orchestrator.
pub struct TimeLockServiceApp;

impl TimeLockServiceApp {
    /// Wrap a payload in a time-lock puzzle.
    ///
    /// # Errors
    /// Returns [`AppError::TimeLock`] on failure.
    pub fn lock(
        payload: &Payload,
        unlock_at: DateTime<Utc>,
        service: &dyn TimeLockServicePort,
    ) -> Result<TimeLockPuzzle, AppError> {
        Ok(service.lock(payload, unlock_at)?)
    }

    /// Solve a time-lock puzzle (blocking).
    ///
    /// # Errors
    /// Returns [`AppError::TimeLock`] on failure.
    pub fn unlock(
        puzzle: &TimeLockPuzzle,
        service: &dyn TimeLockServicePort,
    ) -> Result<Payload, AppError> {
        Ok(service.unlock(puzzle)?)
    }

    /// Non-blocking puzzle check.
    ///
    /// # Errors
    /// Returns [`AppError::TimeLock`] on failure.
    pub fn try_unlock(
        puzzle: &TimeLockPuzzle,
        service: &dyn TimeLockServicePort,
    ) -> Result<Option<Payload>, AppError> {
        Ok(service.try_unlock(puzzle)?)
    }
}

// ─── CanaryShardService ───────────────────────────────────────────────────────

/// Canary shard tripwire orchestrator.
pub struct CanaryShardService;

impl CanaryShardService {
    /// Embed a canary shard alongside distributed covers.
    ///
    /// # Errors
    /// Returns [`AppError::Canary`] on failure.
    pub fn embed_canary(
        covers: Vec<CoverMedia>,
        embedder: &dyn EmbedTechnique,
        canary: &dyn CanaryServicePort,
    ) -> Result<(Vec<CoverMedia>, CanaryShard), AppError> {
        Ok(canary.embed_canary(covers, embedder)?)
    }

    /// Check whether a canary has been accessed.
    pub fn check_canary(shard: &CanaryShard, canary: &dyn CanaryServicePort) -> bool {
        canary.check_canary(shard)
    }
}

// ─── ForensicService ──────────────────────────────────────────────────────────

/// Forensic watermark tripwire orchestrator.
pub struct ForensicService;

impl ForensicService {
    /// Embed a per-recipient watermark into a cover.
    ///
    /// # Errors
    /// Returns [`AppError::Opsec`] on failure.
    pub fn embed_tripwire(
        cover: CoverMedia,
        tag: &WatermarkTripwireTag,
        watermarker: &dyn ForensicWatermarker,
    ) -> Result<CoverMedia, AppError> {
        Ok(watermarker.embed_tripwire(cover, tag)?)
    }

    /// Identify which recipient leaked a stego cover.
    ///
    /// # Errors
    /// Returns [`AppError::Opsec`] on failure.
    pub fn identify_recipient(
        stego: &CoverMedia,
        tags: &[WatermarkTripwireTag],
        watermarker: &dyn ForensicWatermarker,
    ) -> Result<Option<WatermarkReceipt>, AppError> {
        Ok(watermarker.identify_recipient(stego, tags)?)
    }
}

// ─── AmnesiaPipelineService ───────────────────────────────────────────────────

/// Amnesiac in-memory embed/extract orchestrator.
pub struct AmnesiaPipelineService;

impl AmnesiaPipelineService {
    /// Embed a payload entirely in memory — no filesystem writes.
    ///
    /// # Errors
    /// Returns [`AppError::Opsec`] on pipeline failure.
    pub fn embed_in_memory(
        payload_input: &mut dyn Read,
        cover_input: &mut dyn Read,
        output: &mut dyn Write,
        technique: &dyn EmbedTechnique,
        pipeline: &dyn AmnesiaPipeline,
    ) -> Result<(), AppError> {
        Ok(pipeline.embed_in_memory(payload_input, cover_input, output, technique)?)
    }
}

// ─── PanicWipeService ─────────────────────────────────────────────────────────

/// Emergency panic wipe orchestrator.
pub struct PanicWipeService;

impl PanicWipeService {
    /// Securely wipe all paths in `config`.
    ///
    /// # Errors
    /// Returns [`AppError::Opsec`] on failure.
    pub fn wipe(config: &PanicWipeConfig, wiper: &dyn PanicWiper) -> Result<(), AppError> {
        Ok(wiper.wipe(config)?)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{Capacity, CoverMediaKind};
    use std::collections::HashMap;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // ─── Mock Embedder / Extractor ────────────────────────────────────────

    struct MockEmbedder;

    impl EmbedTechnique for MockEmbedder {
        fn technique(&self) -> StegoTechnique {
            StegoTechnique::LsbImage
        }

        fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
            Ok(Capacity {
                bytes: cover.data.len() as u64,
                technique: StegoTechnique::LsbImage,
            })
        }

        fn embed(&self, cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
            let mut data = cover.data.to_vec();
            #[expect(clippy::cast_possible_truncation, reason = "test data < 4 GiB")]
            let len = payload.len() as u32;
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(payload.as_bytes());
            Ok(CoverMedia {
                kind: cover.kind,
                data: Bytes::from(data),
                metadata: cover.metadata,
            })
        }
    }

    struct MockExtractor {
        cover_prefix_len: usize,
    }

    impl ExtractTechnique for MockExtractor {
        fn technique(&self) -> StegoTechnique {
            StegoTechnique::LsbImage
        }

        fn extract(&self, stego: &CoverMedia) -> Result<Payload, StegoError> {
            let data = &stego.data;
            if data.len() <= self.cover_prefix_len + 4 {
                return Err(StegoError::NoPayloadFound);
            }
            let offset = self.cover_prefix_len;
            let len_bytes: [u8; 4] = data
                .get(offset..offset + 4)
                .ok_or(StegoError::NoPayloadFound)?
                .try_into()
                .map_err(|_| StegoError::NoPayloadFound)?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            let start = offset + 4;
            let payload_data = data
                .get(start..start + len)
                .ok_or(StegoError::NoPayloadFound)?;
            Ok(Payload::from_bytes(payload_data.to_vec()))
        }
    }

    fn make_cover(size: usize) -> CoverMedia {
        CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(vec![0u8; size]),
            metadata: HashMap::new(),
        }
    }

    // ─── Embed + Extract ──────────────────────────────────────────────────

    #[test]
    fn embed_extract_round_trip() -> TestResult {
        let cover = make_cover(128);
        let payload = Payload::from_bytes(b"secret message".to_vec());
        let embedder = MockEmbedder;
        let extractor = MockExtractor {
            cover_prefix_len: 128,
        };

        let stego = EmbedService::embed(cover, &payload, &embedder)?;
        let extracted = ExtractService::extract(&stego, &extractor)?;
        assert_eq!(extracted.as_bytes(), b"secret message");
        Ok(())
    }

    // ─── Analyse ──────────────────────────────────────────────────────────

    #[test]
    fn analyse_returns_report() -> TestResult {
        let data: Vec<u8> = (0..=255).cycle().take(8192).collect();
        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(data),
            metadata: HashMap::new(),
        };
        let analyser = crate::adapters::analysis::CapacityAnalyserImpl::new();
        let report = AnalyseService::analyse(&cover, StegoTechnique::LsbImage, &analyser)?;
        assert!(report.cover_capacity.bytes > 0);
        Ok(())
    }

    // ─── Scrub ────────────────────────────────────────────────────────────

    #[test]
    fn scrub_service_normalises_text() -> TestResult {
        let stylo_scrubber = crate::adapters::scrubber::StyloScrubberImpl::new();
        let profile = StyloProfile {
            normalize_punctuation: true,
            target_avg_sentence_len: 15.0,
            target_vocab_size: 1000,
        };
        let scrubbed = ScrubService::scrub("He  can't   stop!!!", &profile, &stylo_scrubber)?;
        assert!(!scrubbed.contains("  "));
        assert!(scrubbed.contains("cannot"));
        Ok(())
    }

    // ─── Archive ──────────────────────────────────────────────────────────

    #[test]
    fn archive_service_round_trip() -> TestResult {
        let handler = crate::adapters::archive::ArchiveHandlerImpl::new();
        let files = vec![("test.txt", b"data" as &[u8])];
        let packed = ArchiveService::pack(&files, ArchiveFormat::Zip, &handler)?;
        let unpacked = ArchiveService::unpack(&packed, ArchiveFormat::Zip, &handler)?;
        assert_eq!(unpacked.len(), 1);
        assert_eq!(
            unpacked.first().ok_or("index out of bounds")?.1.as_ref(),
            b"data"
        );
        Ok(())
    }

    // ─── AppError wraps all domain errors ─────────────────────────────────

    #[test]
    fn app_error_wraps_stego() {
        let stego_err = StegoError::NoPayloadFound;
        let app_err = AppError::from(stego_err);
        assert!(matches!(app_err, AppError::Stego(_)));
    }

    #[test]
    fn app_error_wraps_crypto() {
        let crypto_err = CryptoError::KeyGenFailed {
            reason: "test".into(),
        };
        let app_err = AppError::from(crypto_err);
        assert!(matches!(app_err, AppError::Crypto(_)));
    }

    #[test]
    fn app_error_wraps_distribution() {
        let dist_err = DistributionError::InsufficientCovers { needed: 3, got: 1 };
        let app_err = AppError::from(dist_err);
        assert!(matches!(app_err, AppError::Distribution(_)));
    }

    #[test]
    fn app_error_wraps_deniable() {
        let den_err = DeniableError::InsufficientCapacity;
        let app_err = AppError::from(den_err);
        assert!(matches!(app_err, AppError::Deniable(_)));
    }

    #[test]
    fn app_error_wraps_time_lock() {
        let tl_err = TimeLockError::ComputationFailed {
            reason: "test".into(),
        };
        let app_err = AppError::from(tl_err);
        assert!(matches!(app_err, AppError::TimeLock(_)));
    }

    #[test]
    fn app_error_wraps_corpus() {
        let c_err = CorpusError::IndexError {
            reason: "test".into(),
        };
        let app_err = AppError::from(c_err);
        assert!(matches!(app_err, AppError::Corpus(_)));
    }
}
