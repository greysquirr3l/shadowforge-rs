//! Domain error types for all bounded contexts.
//!
//! Every error variant uses [`thiserror`] and serialises cleanly to JSON.
//! No I/O errors live here — those are adapter concerns.

use thiserror::Error;

// ─── CryptoError ──────────────────────────────────────────────────────────────

/// Errors produced by the crypto bounded context.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation failed.
    #[error("key generation failed: {reason}")]
    KeyGenFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Key encapsulation failed.
    #[error("encapsulation failed: {reason}")]
    EncapsulationFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Key decapsulation failed.
    #[error("decapsulation failed: {reason}")]
    DecapsulationFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Signature creation failed.
    #[error("signing failed: {reason}")]
    SigningFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Signature verification failed (bad key, corrupted data, or forgery).
    #[error("signature verification failed: {reason}")]
    VerificationFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// AES-GCM encryption failed.
    #[error("encryption failed: {reason}")]
    EncryptionFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// AES-GCM decryption or authentication-tag verification failed.
    #[error("decryption failed: {reason}")]
    DecryptionFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// KDF derivation failed (e.g. invalid Argon2 parameters).
    #[error("KDF failed: {reason}")]
    KdfFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Input key material was the wrong length.
    #[error("invalid key length: expected {expected} bytes, got {got}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        got: usize,
    },
    /// Nonce was the wrong length.
    #[error("invalid nonce length: expected {expected} bytes, got {got}")]
    InvalidNonceLength {
        /// Expected nonce length in bytes.
        expected: usize,
        /// Actual nonce length provided.
        got: usize,
    },
}

// ─── CorrectionError ──────────────────────────────────────────────────────────

/// Errors produced by the error-correction bounded context.
#[derive(Debug, Error)]
pub enum CorrectionError {
    /// Too few shards survive to reconstruct the original data.
    #[error("insufficient shards: need {needed}, have {available}")]
    InsufficientShards {
        /// Minimum number of data shards required.
        needed: usize,
        /// Number of valid shards available.
        available: usize,
    },
    /// An HMAC tag did not match the shard contents.
    #[error("HMAC mismatch on shard {index}")]
    HmacMismatch {
        /// Zero-based shard index whose tag failed validation.
        index: u8,
    },
    /// The Reed-Solomon library reported an unrecoverable error.
    #[error("reed-solomon error: {reason}")]
    ReedSolomonError {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Shard set parameters are invalid (e.g. zero data shards).
    #[error("invalid shard parameters: {reason}")]
    InvalidParameters {
        /// Human-readable reason the parameters are invalid.
        reason: String,
    },
}

// ─── StegoError ───────────────────────────────────────────────────────────────

/// Errors produced by the steganography bounded context.
#[derive(Debug, Error)]
pub enum StegoError {
    /// The payload is too large for the selected cover and technique.
    #[error("payload too large: need {needed} bytes, cover holds {available}")]
    PayloadTooLarge {
        /// Number of bytes the payload requires.
        needed: u64,
        /// Number of bytes the cover can hold with this technique.
        available: u64,
    },
    /// The cover medium type is incompatible with the selected technique.
    #[error("unsupported cover type for this technique: {reason}")]
    UnsupportedCoverType {
        /// Human-readable description of the incompatibility.
        reason: String,
    },
    /// Raw pixel or sample data is malformed or truncated.
    #[error("malformed cover data: {reason}")]
    MalformedCoverData {
        /// Human-readable reason the data is malformed.
        reason: String,
    },
    /// No hidden payload was found during extraction.
    #[error("no payload found in stego cover")]
    NoPayloadFound,
    /// Extraction produced data that failed integrity checks.
    #[error("extracted data failed integrity check: {reason}")]
    IntegrityCheckFailed {
        /// Human-readable description of what failed.
        reason: String,
    },
}

// ─── MediaError ───────────────────────────────────────────────────────────────

/// Errors produced by the media bounded context.
#[derive(Debug, Error)]
pub enum MediaError {
    /// The file format is not supported by any registered codec.
    #[error("unsupported media format: {extension}")]
    UnsupportedFormat {
        /// File extension or MIME type that was rejected.
        extension: String,
    },
    /// Decoding the raw file bytes failed.
    #[error("decode error: {reason}")]
    DecodeFailed {
        /// Human-readable reason for the decode failure.
        reason: String,
    },
    /// Encoding the decoded data back to bytes failed.
    #[error("encode error: {reason}")]
    EncodeFailed {
        /// Human-readable reason for the encode failure.
        reason: String,
    },
    /// A filesystem path was invalid or unreadable (adapter-level only).
    #[error("IO error: {reason}")]
    IoError {
        /// Human-readable description of the IO problem.
        reason: String,
    },
}

// ─── PdfError ─────────────────────────────────────────────────────────────────

/// Errors produced by the PDF bounded context.
#[derive(Debug, Error)]
pub enum PdfError {
    /// The PDF document could not be parsed.
    #[error("PDF parse error: {reason}")]
    ParseFailed {
        /// Human-readable reason for the parse failure.
        reason: String,
    },
    /// Page rasterisation via pdfium failed.
    #[error("page render error on page {page}: {reason}")]
    RenderFailed {
        /// Zero-based page index that failed to render.
        page: usize,
        /// Human-readable reason for the render failure.
        reason: String,
    },
    /// Rebuilding a PDF from rasterised pages failed.
    #[error("PDF rebuild error: {reason}")]
    RebuildFailed {
        /// Human-readable reason for the rebuild failure.
        reason: String,
    },
    /// Content-stream or metadata embedding failed.
    #[error("PDF embed error: {reason}")]
    EmbedFailed {
        /// Human-readable reason for the embed failure.
        reason: String,
    },
    /// Content-stream or metadata extraction failed.
    #[error("PDF extract error: {reason}")]
    ExtractFailed {
        /// Human-readable reason for the extract failure.
        reason: String,
    },
    /// A filesystem path was invalid or unreadable (adapter-level only).
    #[error("IO error: {reason}")]
    IoError {
        /// Human-readable description of the IO problem.
        reason: String,
    },
    /// The PDF document is encrypted and cannot be processed.
    #[error("PDF is encrypted and cannot be processed")]
    Encrypted,
    /// Failed to bind or load the pdfium shared library at runtime.
    #[error("pdfium library binding failed: {reason}")]
    BindFailed {
        /// Details about which binding attempts were tried and why they failed.
        reason: String,
    },
}

// ─── DistributionError ────────────────────────────────────────────────────────

/// Errors produced by the distribution bounded context.
#[derive(Debug, Error)]
pub enum DistributionError {
    /// Fewer covers were provided than the distribution pattern requires.
    #[error("insufficient covers: need {needed}, got {got}")]
    InsufficientCovers {
        /// Minimum number of covers the pattern needs.
        needed: usize,
        /// Number of covers actually provided.
        got: usize,
    },
    /// An embedding step failed during distribution.
    #[error("embed failed on cover {index}: {source}")]
    EmbedFailed {
        /// Zero-based cover index at which embedding failed.
        index: usize,
        /// The underlying stego error.
        #[source]
        source: StegoError,
    },
    /// Error-correction encoding failed during shard production.
    #[error("error correction failed: {source}")]
    CorrectionFailed {
        /// The underlying correction error.
        #[source]
        source: CorrectionError,
    },
}

// ─── ReconstructionError ──────────────────────────────────────────────────────

/// Errors produced by the reconstruction bounded context.
#[derive(Debug, Error)]
pub enum ReconstructionError {
    /// Not enough valid stego covers were provided.
    #[error("insufficient covers for reconstruction: need {needed}, got {got}")]
    InsufficientCovers {
        /// Minimum required covers.
        needed: usize,
        /// Covers actually provided.
        got: usize,
    },
    /// Payload extraction from a stego cover failed.
    #[error("extraction failed on cover {index}: {source}")]
    ExtractionFailed {
        /// Zero-based cover index at which extraction failed.
        index: usize,
        /// The underlying stego error.
        #[source]
        source: StegoError,
    },
    /// Error-correction decoding failed.
    #[error("error correction failed: {source}")]
    CorrectionFailed {
        /// The underlying correction error.
        #[source]
        source: CorrectionError,
    },
    /// Manifest signature verification failed.
    #[error("manifest verification failed: {reason}")]
    ManifestVerificationFailed {
        /// Human-readable reason the manifest failed.
        reason: String,
    },
}

// ─── AnalysisError ────────────────────────────────────────────────────────────

/// Errors produced by the analysis bounded context.
#[derive(Debug, Error)]
pub enum AnalysisError {
    /// The cover medium type is incompatible with the requested technique.
    #[error("unsupported cover type for analysis: {reason}")]
    UnsupportedCoverType {
        /// Human-readable description of the incompatibility.
        reason: String,
    },
    /// Statistical computation failed (e.g. divide-by-zero on empty cover).
    #[error("statistical computation failed: {reason}")]
    ComputationFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ─── ArchiveError ─────────────────────────────────────────────────────────────

/// Errors produced by the archive bounded context.
#[derive(Debug, Error)]
pub enum ArchiveError {
    /// Packing files into the archive failed.
    #[error("archive pack error: {reason}")]
    PackFailed {
        /// Human-readable reason for the pack failure.
        reason: String,
    },
    /// Unpacking the archive failed.
    #[error("archive unpack error: {reason}")]
    UnpackFailed {
        /// Human-readable reason for the unpack failure.
        reason: String,
    },
    /// The archive format is not supported.
    #[error("unsupported archive format: {reason}")]
    UnsupportedFormat {
        /// Human-readable description of the unsupported format.
        reason: String,
    },
}

// ─── AdaptiveError ────────────────────────────────────────────────────────────

/// Errors produced by the adaptive embedding bounded context.
#[derive(Debug, Error)]
pub enum AdaptiveError {
    /// The optimiser failed to find an embedding that meets the detectability budget.
    #[error(
        "could not meet detectability budget of {target_db:.2} dB: best was {achieved_db:.2} dB"
    )]
    BudgetNotMet {
        /// Target detectability ceiling in decibels.
        target_db: f64,
        /// Best detectability achieved in decibels.
        achieved_db: f64,
    },
    /// Camera model fingerprint matching failed.
    #[error("profile matching failed: {reason}")]
    ProfileMatchFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Compression simulation failed.
    #[error("compression simulation failed: {reason}")]
    CompressionSimFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// The underlying stego operation failed.
    #[error("stego error during adaptive optimisation: {source}")]
    StegoFailed {
        /// The underlying stego error.
        #[source]
        source: StegoError,
    },
    /// The distributor returned a different number of covers than were supplied.
    #[error("distribution cover count mismatch: got {got}, expected {expected}")]
    DistributionCountMismatch {
        /// Number of covers returned by the distributor.
        got: usize,
        /// Number of covers originally supplied.
        expected: usize,
    },
}

// ─── DeniableError ────────────────────────────────────────────────────────────

/// Errors produced by the deniable steganography bounded context.
#[derive(Debug, Error)]
pub enum DeniableError {
    /// The cover cannot hold both the real and decoy payload simultaneously.
    #[error("cover capacity too small for dual-payload embedding")]
    InsufficientCapacity,
    /// Embedding one of the payloads failed.
    #[error("dual embed failed: {reason}")]
    EmbedFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Extraction with the provided key failed.
    #[error("extraction failed for provided key: {reason}")]
    ExtractionFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ─── OpsecError ───────────────────────────────────────────────────────────────

/// Errors produced by the operational security bounded context.
#[derive(Debug, Error)]
pub enum OpsecError {
    /// A wipe step failed but execution continued.
    #[error("wipe step failed for path {path}: {reason}")]
    WipeStepFailed {
        /// Path that could not be wiped.
        path: String,
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// The in-memory pipeline produced corrupt output.
    #[error("amnesiac pipeline error: {reason}")]
    PipelineError {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Forensic watermark embedding or identification failed.
    #[error("watermark error: {reason}")]
    WatermarkError {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Geographic manifest validation failed.
    #[error("geographic manifest error: {reason}")]
    ManifestError {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ─── CanaryError ──────────────────────────────────────────────────────────────

/// Errors produced by the canary bounded context.
#[derive(Debug, Error)]
pub enum CanaryError {
    /// No covers were provided to embed the canary shard into.
    #[error("no covers provided for canary embedding")]
    NoCovers,
    /// Embedding the canary shard failed.
    #[error("canary embed failed: {source}")]
    EmbedFailed {
        /// The underlying stego error.
        #[source]
        source: StegoError,
    },
}

// ─── DeadDropError ────────────────────────────────────────────────────────────

/// Errors produced by the dead drop bounded context.
#[derive(Debug, Error)]
pub enum DeadDropError {
    /// The platform profile is unknown or unsupported.
    #[error("unsupported platform for dead drop: {reason}")]
    UnsupportedPlatform {
        /// Human-readable description of the issue.
        reason: String,
    },
    /// Encoding for the platform failed.
    #[error("dead drop encode failed: {reason}")]
    EncodeFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ─── TimeLockError ────────────────────────────────────────────────────────────

/// Errors produced by the time-lock bounded context.
#[derive(Debug, Error)]
pub enum TimeLockError {
    /// The puzzle is not yet solvable (unlock time has not been reached).
    #[error("time-lock puzzle not yet solvable; unlock at {unlock_at}")]
    NotYetSolvable {
        /// ISO 8601 string of the earliest unlock time.
        unlock_at: String,
    },
    /// The sequential squaring computation overflowed or failed.
    #[error("puzzle computation failed: {reason}")]
    ComputationFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Decryption of the time-locked ciphertext failed.
    #[error("time-lock decrypt failed: {source}")]
    DecryptFailed {
        /// The underlying crypto error.
        #[source]
        source: CryptoError,
    },
}

// ─── ScrubberError ────────────────────────────────────────────────────────────

/// Errors produced by the stylometric scrubber bounded context.
#[derive(Debug, Error)]
pub enum ScrubberError {
    /// The input text is not valid UTF-8.
    #[error("input is not valid UTF-8: {reason}")]
    InvalidUtf8 {
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// Scrubbing failed to satisfy the target stylometric profile.
    #[error("could not satisfy stylo profile: {reason}")]
    ProfileNotSatisfied {
        /// Human-readable reason the profile could not be satisfied.
        reason: String,
    },
}

// ─── CorpusError ──────────────────────────────────────────────────────────────

/// Errors produced by the corpus steganography bounded context.
#[derive(Debug, Error)]
pub enum CorpusError {
    /// No suitable corpus entry was found for the given payload.
    #[error("no suitable corpus cover found for payload of {payload_bytes} bytes")]
    NoSuitableCover {
        /// Size of the payload in bytes.
        payload_bytes: u64,
    },
    /// The corpus index file is missing or corrupt.
    #[error("corpus index error: {reason}")]
    IndexError {
        /// Human-readable description of the index problem.
        reason: String,
    },
    /// A file could not be added to the corpus index.
    #[error("corpus add failed for path {path}: {reason}")]
    AddFailed {
        /// The path that could not be indexed.
        path: String,
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_error_display_does_not_panic() {
        let e = CryptoError::InvalidKeyLength {
            expected: 32,
            got: 16,
        };
        assert!(e.to_string().contains("32"));
    }

    #[test]
    fn correction_error_display_does_not_panic() {
        let e = CorrectionError::InsufficientShards {
            needed: 5,
            available: 2,
        };
        assert!(e.to_string().contains('5'));
    }

    #[test]
    fn stego_error_display_does_not_panic() {
        let e = StegoError::PayloadTooLarge {
            needed: 1024,
            available: 512,
        };
        assert!(e.to_string().contains("1024"));
    }

    #[test]
    fn all_error_variants_display_without_panic() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(CryptoError::KeyGenFailed {
                reason: "test".into(),
            }),
            Box::new(CorrectionError::HmacMismatch { index: 3 }),
            Box::new(StegoError::NoPayloadFound),
            Box::new(MediaError::UnsupportedFormat {
                extension: "xyz".into(),
            }),
            Box::new(PdfError::ParseFailed {
                reason: "test".into(),
            }),
            Box::new(DistributionError::InsufficientCovers { needed: 3, got: 1 }),
            Box::new(ReconstructionError::InsufficientCovers { needed: 3, got: 1 }),
            Box::new(AnalysisError::ComputationFailed {
                reason: "test".into(),
            }),
            Box::new(ArchiveError::PackFailed {
                reason: "test".into(),
            }),
            Box::new(AdaptiveError::BudgetNotMet {
                target_db: 40.0,
                achieved_db: 35.5,
            }),
            Box::new(DeniableError::InsufficientCapacity),
            Box::new(OpsecError::PipelineError {
                reason: "test".into(),
            }),
            Box::new(CanaryError::NoCovers),
            Box::new(DeadDropError::UnsupportedPlatform {
                reason: "test".into(),
            }),
            Box::new(TimeLockError::NotYetSolvable {
                unlock_at: "2030-01-01T00:00:00Z".into(),
            }),
            Box::new(ScrubberError::InvalidUtf8 {
                reason: "test".into(),
            }),
            Box::new(CorpusError::NoSuitableCover {
                payload_bytes: 1024,
            }),
        ];
        for e in &errors {
            // Must not panic and must produce a non-empty string.
            assert!(!e.to_string().is_empty(), "empty display for {e:?}");
        }
    }
}
