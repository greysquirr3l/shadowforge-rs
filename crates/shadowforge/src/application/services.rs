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
    use crate::domain::types::{Capacity, CoverMediaKind, Shard};
    use std::collections::HashMap;
    use uuid::Uuid;

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

    // ─── KeyGenService ────────────────────────────────────────────────────

    struct MockEncryptor;

    impl Encryptor for MockEncryptor {
        fn generate_keypair(&self) -> Result<KeyPair, CryptoError> {
            Ok(KeyPair {
                public_key: vec![1u8; 32],
                secret_key: vec![2u8; 64],
            })
        }

        fn encapsulate(&self, _public_key: &[u8]) -> Result<(Bytes, Bytes), CryptoError> {
            Ok((Bytes::from(vec![3u8; 32]), Bytes::from(vec![4u8; 32])))
        }

        fn decapsulate(
            &self,
            _secret_key: &[u8],
            _ciphertext: &[u8],
        ) -> Result<Bytes, CryptoError> {
            Ok(Bytes::from(vec![4u8; 32]))
        }
    }

    struct MockSigner;

    impl Signer for MockSigner {
        fn generate_keypair(&self) -> Result<KeyPair, CryptoError> {
            Ok(KeyPair {
                public_key: vec![5u8; 32],
                secret_key: vec![6u8; 32],
            })
        }

        fn sign(&self, _secret_key: &[u8], _message: &[u8]) -> Result<Signature, CryptoError> {
            Ok(Signature(Bytes::from(vec![7u8; 64])))
        }

        fn verify(
            &self,
            _public_key: &[u8],
            _message: &[u8],
            _signature: &Signature,
        ) -> Result<bool, CryptoError> {
            Ok(true)
        }
    }

    #[test]
    fn keygen_generate_keypair() -> TestResult {
        let encryptor = MockEncryptor;
        let kp = KeyGenService::generate_keypair(&encryptor)?;
        assert_eq!(kp.public_key.len(), 32);
        assert_eq!(kp.secret_key.len(), 64);
        Ok(())
    }

    #[test]
    fn keygen_generate_signing_keypair() -> TestResult {
        let signer = MockSigner;
        let kp = KeyGenService::generate_signing_keypair(&signer)?;
        assert_eq!(kp.public_key.len(), 32);
        assert_eq!(kp.secret_key.len(), 32);
        Ok(())
    }

    #[test]
    fn keygen_sign_and_verify() -> TestResult {
        let signer = MockSigner;
        let signature = KeyGenService::sign(&signer, &[0u8; 32], b"test message")?;
        assert_eq!(signature.0.len(), 64);
        let valid = KeyGenService::verify(&signer, &[0u8; 32], b"test message", &signature)?;
        assert!(valid);
        Ok(())
    }

    // ─── DistributeService ────────────────────────────────────────────────

    struct MockDistributor;

    impl crate::domain::ports::Distributor for MockDistributor {
        fn distribute(
            &self,
            _payload: &Payload,
            _profile: &EmbeddingProfile,
            covers: Vec<CoverMedia>,
            _embedder: &dyn EmbedTechnique,
        ) -> Result<Vec<CoverMedia>, DistributionError> {
            Ok(covers)
        }
    }

    #[test]
    fn distribute_service_returns_covers() -> TestResult {
        let payload = Payload::from_bytes(b"payload".to_vec());
        let covers = vec![make_cover(64), make_cover(64)];
        let profile = EmbeddingProfile::Standard;
        let distributor = MockDistributor;
        let embedder = MockEmbedder;
        let result =
            DistributeService::distribute(&payload, covers, &profile, &distributor, &embedder)?;
        assert_eq!(result.len(), 2);
        Ok(())
    }

    // ─── ReconstructService ───────────────────────────────────────────────

    struct MockReconstructor;

    impl crate::domain::ports::Reconstructor for MockReconstructor {
        fn reconstruct(
            &self,
            _covers: Vec<CoverMedia>,
            _extractor: &dyn ExtractTechnique,
            _progress_cb: &dyn Fn(usize, usize),
        ) -> Result<Payload, ReconstructionError> {
            Ok(Payload::from_bytes(b"reconstructed".to_vec()))
        }
    }

    #[test]
    fn reconstruct_service_returns_payload() -> TestResult {
        let stego = vec![make_cover(128)];
        let extractor = MockExtractor {
            cover_prefix_len: 128,
        };
        let reconstructor = MockReconstructor;
        let payload =
            ReconstructService::reconstruct(stego, &extractor, &reconstructor, &|_, _| {})?;
        assert_eq!(payload.as_bytes(), b"reconstructed");
        Ok(())
    }

    // ─── DeniableEmbedService ─────────────────────────────────────────────

    struct MockDeniableEmbedder;

    impl DeniableEmbedder for MockDeniableEmbedder {
        fn embed_dual(
            &self,
            cover: CoverMedia,
            _pair: &DeniablePayloadPair,
            _keys: &DeniableKeySet,
            _embedder: &dyn EmbedTechnique,
        ) -> Result<CoverMedia, crate::domain::errors::DeniableError> {
            Ok(cover)
        }

        fn extract_with_key(
            &self,
            _stego: &CoverMedia,
            _key: &[u8],
            _extractor: &dyn ExtractTechnique,
        ) -> Result<Payload, crate::domain::errors::DeniableError> {
            Ok(Payload::from_bytes(b"deniable".to_vec()))
        }
    }

    #[test]
    fn deniable_embed_service_round_trip() -> TestResult {
        let cover = make_cover(256);
        let pair = DeniablePayloadPair {
            real_payload: b"real".to_vec(),
            decoy_payload: b"decoy".to_vec(),
        };
        let keys = DeniableKeySet {
            primary_key: vec![1u8; 32],
            decoy_key: vec![2u8; 32],
        };
        let embedder = MockEmbedder;
        let deniable = MockDeniableEmbedder;

        let stego = DeniableEmbedService::embed_dual(cover, &pair, &keys, &embedder, &deniable)?;
        let extracted = DeniableEmbedService::extract_with_key(
            &stego,
            &[1u8; 32],
            &MockExtractor {
                cover_prefix_len: 256,
            },
            &deniable,
        )?;
        assert_eq!(extracted.as_bytes(), b"deniable");
        Ok(())
    }

    // ─── DeadDropService ──────────────────────────────────────────────────

    struct MockDeadDropEncoder;

    impl DeadDropEncoder for MockDeadDropEncoder {
        fn encode_for_platform(
            &self,
            cover: CoverMedia,
            _payload: &Payload,
            _platform: &PlatformProfile,
            _embedder: &dyn EmbedTechnique,
        ) -> Result<CoverMedia, DeadDropError> {
            Ok(cover)
        }
    }

    #[test]
    fn dead_drop_service_encode() -> TestResult {
        let cover = make_cover(128);
        let payload = Payload::from_bytes(b"secret".to_vec());
        let platform = PlatformProfile::Instagram;
        let embedder = MockEmbedder;
        let encoder = MockDeadDropEncoder;
        let result = DeadDropService::encode(cover, &payload, &platform, &embedder, &encoder)?;
        assert_eq!(result.kind, CoverMediaKind::PngImage);
        Ok(())
    }

    // ─── TimeLockServiceApp ───────────────────────────────────────────────

    struct MockTimeLockService;

    impl TimeLockServicePort for MockTimeLockService {
        fn lock(
            &self,
            payload: &Payload,
            unlock_at: DateTime<Utc>,
        ) -> Result<TimeLockPuzzle, TimeLockError> {
            Ok(TimeLockPuzzle {
                ciphertext: Bytes::from(payload.as_bytes().to_vec()),
                modulus: vec![1],
                start_value: vec![2],
                squarings_required: 100,
                created_at: Utc::now(),
                unlock_at,
            })
        }

        fn unlock(&self, puzzle: &TimeLockPuzzle) -> Result<Payload, TimeLockError> {
            Ok(Payload::from_bytes(puzzle.ciphertext.to_vec()))
        }

        fn try_unlock(&self, puzzle: &TimeLockPuzzle) -> Result<Option<Payload>, TimeLockError> {
            Ok(Some(Payload::from_bytes(puzzle.ciphertext.to_vec())))
        }
    }

    #[test]
    fn time_lock_service_lock_and_unlock() -> TestResult {
        let payload = Payload::from_bytes(b"time locked".to_vec());
        let service = MockTimeLockService;
        let puzzle = TimeLockServiceApp::lock(&payload, Utc::now(), &service)?;
        let recovered = TimeLockServiceApp::unlock(&puzzle, &service)?;
        assert_eq!(recovered.as_bytes(), b"time locked");
        Ok(())
    }

    #[test]
    fn time_lock_service_try_unlock() -> TestResult {
        let payload = Payload::from_bytes(b"try me".to_vec());
        let service = MockTimeLockService;
        let puzzle = TimeLockServiceApp::lock(&payload, Utc::now(), &service)?;
        let result = TimeLockServiceApp::try_unlock(&puzzle, &service)?;
        let recovered = result.ok_or("expected Some")?;
        assert_eq!(recovered.as_bytes(), b"try me");
        Ok(())
    }

    // ─── CanaryShardService ───────────────────────────────────────────────

    struct MockCanaryService;

    impl CanaryServicePort for MockCanaryService {
        fn embed_canary(
            &self,
            covers: Vec<CoverMedia>,
            _embedder: &dyn EmbedTechnique,
        ) -> Result<(Vec<CoverMedia>, CanaryShard), CanaryError> {
            let shard = CanaryShard {
                shard: Shard {
                    index: 99,
                    total: 100,
                    data: vec![0u8; 16],
                    hmac_tag: [0u8; 32],
                },
                canary_id: Uuid::new_v4(),
                notify_url: Some("https://example.com/canary".into()),
            };
            Ok((covers, shard))
        }

        fn check_canary(&self, _shard: &CanaryShard) -> bool {
            false
        }
    }

    #[test]
    fn canary_shard_service_embed_and_check() -> TestResult {
        let covers = vec![make_cover(64)];
        let embedder = MockEmbedder;
        let canary = MockCanaryService;
        let (result_covers, shard) = CanaryShardService::embed_canary(covers, &embedder, &canary)?;
        assert_eq!(result_covers.len(), 1);
        assert_eq!(shard.shard.index, 99);
        assert!(!CanaryShardService::check_canary(&shard, &canary));
        Ok(())
    }

    // ─── ForensicService ──────────────────────────────────────────────────

    struct MockForensicWatermarker;

    impl ForensicWatermarker for MockForensicWatermarker {
        fn embed_tripwire(
            &self,
            cover: CoverMedia,
            _tag: &WatermarkTripwireTag,
        ) -> Result<CoverMedia, OpsecError> {
            Ok(cover)
        }

        fn identify_recipient(
            &self,
            _stego: &CoverMedia,
            tags: &[WatermarkTripwireTag],
        ) -> Result<Option<WatermarkReceipt>, OpsecError> {
            if tags.is_empty() {
                return Ok(None);
            }
            Ok(Some(WatermarkReceipt {
                recipient: tags
                    .first()
                    .map_or_else(String::new, |t| t.recipient_id.to_string()),
                algorithm: "lsb".into(),
                shards: vec![0],
                created_at: Utc::now(),
            }))
        }
    }

    #[test]
    fn forensic_service_embed_and_identify() -> TestResult {
        let cover = make_cover(128);
        let tag = WatermarkTripwireTag {
            recipient_id: Uuid::new_v4(),
            embedding_seed: vec![9u8; 16],
        };
        let watermarker = MockForensicWatermarker;

        let stego = ForensicService::embed_tripwire(cover, &tag, &watermarker)?;
        let receipt = ForensicService::identify_recipient(&stego, &[tag], &watermarker)?;
        let r = receipt.ok_or("expected Some")?;
        assert!(!r.recipient.is_empty());
        assert_eq!(r.algorithm, "lsb");
        Ok(())
    }

    #[test]
    fn forensic_service_identify_no_tags() -> TestResult {
        let cover = make_cover(128);
        let watermarker = MockForensicWatermarker;
        let receipt = ForensicService::identify_recipient(&cover, &[], &watermarker)?;
        assert!(receipt.is_none());
        Ok(())
    }

    // ─── PanicWipeService ─────────────────────────────────────────────────

    struct MockPanicWiper;

    impl PanicWiper for MockPanicWiper {
        fn wipe(&self, _config: &PanicWipeConfig) -> Result<(), OpsecError> {
            Ok(())
        }
    }

    #[test]
    fn panic_wipe_service_succeeds() -> TestResult {
        let wiper = MockPanicWiper;
        let config = PanicWipeConfig {
            key_paths: vec![],
            config_paths: vec![],
            temp_dirs: vec![],
        };
        PanicWipeService::wipe(&config, &wiper)?;
        Ok(())
    }

    // ─── AmnesiaPipelineService ───────────────────────────────────────────

    struct MockAmnesiaPipeline;

    impl AmnesiaPipeline for MockAmnesiaPipeline {
        fn embed_in_memory(
            &self,
            payload_input: &mut dyn Read,
            _cover_input: &mut dyn Read,
            output: &mut dyn Write,
            _technique: &dyn EmbedTechnique,
        ) -> Result<(), OpsecError> {
            let mut buf = Vec::new();
            payload_input
                .read_to_end(&mut buf)
                .map_err(|e| OpsecError::PipelineError {
                    reason: e.to_string(),
                })?;
            output
                .write_all(&buf)
                .map_err(|e| OpsecError::PipelineError {
                    reason: e.to_string(),
                })?;
            Ok(())
        }
    }

    #[test]
    fn amnesia_pipeline_service_embed() -> TestResult {
        let pipeline = MockAmnesiaPipeline;
        let embedder = MockEmbedder;
        let mut payload_input = std::io::Cursor::new(b"secret payload");
        let mut cover_input = std::io::Cursor::new(vec![0u8; 128]);
        let mut output = Vec::new();

        AmnesiaPipelineService::embed_in_memory(
            &mut payload_input,
            &mut cover_input,
            &mut output,
            &embedder,
            &pipeline,
        )?;

        assert_eq!(output, b"secret payload");
        Ok(())
    }

    // ─── Remaining AppError coverage ──────────────────────────────────────

    #[test]
    fn app_error_wraps_reconstruction() {
        let err = ReconstructionError::InsufficientCovers { needed: 3, got: 1 };
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::Reconstruction(_)));
    }

    #[test]
    fn app_error_wraps_correction() {
        let err = CorrectionError::InsufficientShards {
            needed: 3,
            available: 1,
        };
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::Correction(_)));
    }

    #[test]
    fn app_error_wraps_analysis() {
        let err = AnalysisError::UnsupportedCoverType {
            reason: "test".into(),
        };
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::Analysis(_)));
    }

    #[test]
    fn app_error_wraps_archive() {
        let err = ArchiveError::PackFailed {
            reason: "test".into(),
        };
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::Archive(_)));
    }

    #[test]
    fn app_error_wraps_opsec() {
        let err = OpsecError::PipelineError {
            reason: "test".into(),
        };
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::Opsec(_)));
    }

    #[test]
    fn app_error_wraps_scrubber() {
        let err = ScrubberError::ProfileNotSatisfied {
            reason: "test".into(),
        };
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::Scrubber(_)));
    }

    #[test]
    fn app_error_wraps_adaptive() {
        let err = AdaptiveError::BudgetNotMet {
            achieved_db: -5.0,
            target_db: -10.0,
        };
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::Adaptive(_)));
    }

    #[test]
    fn app_error_wraps_canary() {
        let err = CanaryError::EmbedFailed {
            source: StegoError::NoPayloadFound,
        };
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::Canary(_)));
    }

    #[test]
    fn app_error_wraps_dead_drop() {
        let err = DeadDropError::EncodeFailed {
            reason: "test".into(),
        };
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::DeadDrop(_)));
    }

    #[test]
    fn app_error_display_formats() {
        let err = AppError::Crypto(CryptoError::KeyGenFailed {
            reason: "oops".into(),
        });
        let msg = format!("{err}");
        assert!(msg.contains("crypto"));
        assert!(msg.contains("oops"));
    }
}
