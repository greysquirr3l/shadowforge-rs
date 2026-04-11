//! Adapter implementing the [`Distributor`] port for all four distribution
//! patterns: 1:1, 1:N, N:1, N:M.

use crate::domain::distribution::{assign_many_to_many, assign_one_to_many, validate_cover_count};
use crate::domain::errors::DistributionError;
use crate::domain::ports::{Distributor, EmbedTechnique};
use crate::domain::types::{CoverMedia, DistributionPattern, EmbeddingProfile, Payload};

/// Concrete [`Distributor`] implementation.
pub struct DistributorImpl {
    /// HMAC key for shard integrity tags.
    hmac_key: Vec<u8>,
    /// Optional explicit shard topology from CLI.
    shard_config: Option<(u8, u8)>,
}

impl Default for DistributorImpl {
    fn default() -> Self {
        Self::new(Self::generate_hmac_key())
    }
}

impl DistributorImpl {
    /// Create a new distributor with the given HMAC key.
    #[must_use]
    pub const fn new(hmac_key: Vec<u8>) -> Self {
        Self {
            hmac_key,
            shard_config: None,
        }
    }

    /// Create a new distributor with explicit data/parity shard counts.
    #[must_use]
    pub const fn new_with_shard_config(
        hmac_key: Vec<u8>,
        data_shards: u8,
        parity_shards: u8,
    ) -> Self {
        Self {
            hmac_key,
            shard_config: Some((data_shards, parity_shards)),
        }
    }

    /// Generate a random 32-byte HMAC key.
    #[must_use]
    pub fn generate_hmac_key() -> Vec<u8> {
        use rand::Rng;
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    /// Return a reference to the HMAC key used for shard integrity.
    #[must_use]
    pub fn hmac_key(&self) -> &[u8] {
        &self.hmac_key
    }
}

impl Distributor for DistributorImpl {
    fn distribute(
        &self,
        payload: &Payload,
        profile: &EmbeddingProfile,
        covers: Vec<CoverMedia>,
        embedder: &dyn EmbedTechnique,
    ) -> Result<Vec<CoverMedia>, DistributionError> {
        let pattern = pattern_from_profile(profile, covers.len(), self.shard_config);
        validate_cover_count(&pattern, covers.len())?;

        match pattern {
            DistributionPattern::OneToOne => distribute_one_to_one(payload, covers, embedder),
            DistributionPattern::OneToMany {
                data_shards,
                parity_shards,
            } => distribute_one_to_many(
                payload,
                covers,
                embedder,
                data_shards,
                parity_shards,
                &self.hmac_key,
            ),
            DistributionPattern::ManyToOne => {
                // For ManyToOne called via the trait with a single payload,
                // just embed directly (multi-payload packing is done upstream).
                distribute_one_to_one(payload, covers, embedder)
            }
            DistributionPattern::ManyToMany { mode } => {
                distribute_many_to_many(payload, covers, embedder, mode)
            }
        }
    }
}

/// Map an [`EmbeddingProfile`] to a default [`DistributionPattern`].
///
/// The adapter infers the distribution pattern from the profile and cover
/// count rather than forcing the caller to specify both.
fn pattern_from_profile(
    profile: &EmbeddingProfile,
    cover_count: usize,
    shard_config: Option<(u8, u8)>,
) -> DistributionPattern {
    // Default to OneToOne for single cover, OneToMany otherwise.
    // Non-standard profiles retain distribution topology and influence embedding behavior.
    let default_one_to_many = || {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "cover_count bounded by caller"
        )]
        let data = (cover_count.saturating_sub(1)) as u8;
        DistributionPattern::OneToMany {
            data_shards: data.max(1),
            parity_shards: 1,
        }
    };

    let explicit_one_to_many =
        |data_shards: u8, parity_shards: u8| DistributionPattern::OneToMany {
            data_shards: data_shards.max(1),
            parity_shards: parity_shards.max(1),
        };

    let one_to_many = |shard_config: Option<(u8, u8)>| {
        shard_config.map_or_else(default_one_to_many, |(data_shards, parity_shards)| {
            explicit_one_to_many(data_shards, parity_shards)
        })
    };

    match profile {
        EmbeddingProfile::Standard
        | EmbeddingProfile::Adaptive { .. }
        | EmbeddingProfile::CompressionSurvivable { .. } => {
            if cover_count <= 1 {
                DistributionPattern::OneToOne
            } else {
                one_to_many(shard_config)
            }
        }
        EmbeddingProfile::CorpusBased => DistributionPattern::OneToOne,
    }
}

/// 1:1 — embed the payload into the first cover.
fn distribute_one_to_one(
    payload: &Payload,
    mut covers: Vec<CoverMedia>,
    embedder: &dyn EmbedTechnique,
) -> Result<Vec<CoverMedia>, DistributionError> {
    if covers.is_empty() {
        return Err(DistributionError::InsufficientCovers { needed: 1, got: 0 });
    }
    let cover = covers.remove(0);
    let stego = embedder
        .embed(cover, payload)
        .map_err(|source| DistributionError::EmbedFailed { index: 0, source })?;
    let mut result = vec![stego];
    result.extend(covers);
    Ok(result)
}

/// 1:N — split payload into shards, embed each in a cover.
fn distribute_one_to_many(
    payload: &Payload,
    covers: Vec<CoverMedia>,
    embedder: &dyn EmbedTechnique,
    data_shards: u8,
    parity_shards: u8,
    hmac_key: &[u8],
) -> Result<Vec<CoverMedia>, DistributionError> {
    use crate::domain::correction::encode_shards;

    let shards = encode_shards(payload.as_bytes(), data_shards, parity_shards, hmac_key)
        .map_err(|source| DistributionError::CorrectionFailed { source })?;

    let assignments = assign_one_to_many(shards.len(), covers.len());
    let mut result = covers;

    for (shard_idx, cover_idx) in assignments {
        let shard = shards
            .get(shard_idx)
            .ok_or_else(|| DistributionError::InsufficientCovers {
                needed: shard_idx.strict_add(1),
                got: shards.len(),
            })?;
        let shard_payload = Payload::from_bytes(shard.data.clone());
        let cover = result.remove(cover_idx);
        let stego = embedder.embed(cover, &shard_payload).map_err(|source| {
            DistributionError::EmbedFailed {
                index: cover_idx,
                source,
            }
        })?;
        result.insert(cover_idx, stego);
    }

    Ok(result)
}

/// M:N — assign shards to covers by mode.
fn distribute_many_to_many(
    payload: &Payload,
    covers: Vec<CoverMedia>,
    embedder: &dyn EmbedTechnique,
    mode: crate::domain::types::ManyToManyMode,
) -> Result<Vec<CoverMedia>, DistributionError> {
    // For many-to-many, treat the payload as shards spread across covers
    let cover_count = covers.len();
    // Simple: split payload into cover_count equal chunks
    let chunk_size = (payload.len().strict_add(cover_count).strict_sub(1)) / cover_count;
    let chunks: Vec<Payload> = payload
        .as_bytes()
        .chunks(chunk_size)
        .map(|c| Payload::from_bytes(c.to_vec()))
        .collect();

    let assignments = assign_many_to_many(mode, chunks.len(), cover_count, 42);
    let mut result = covers;

    for (shard_idx, cover_indices) in assignments.iter().enumerate() {
        let Some(chunk) = chunks.get(shard_idx) else {
            break;
        };
        for &cover_idx in cover_indices {
            let cover = result.remove(cover_idx);
            let stego =
                embedder
                    .embed(cover, chunk)
                    .map_err(|source| DistributionError::EmbedFailed {
                        index: cover_idx,
                        source,
                    })?;
            result.insert(cover_idx, stego);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::distribution::pack_many_payloads;
    use crate::domain::errors::StegoError;
    use crate::domain::types::{Capacity, CoverMedia, CoverMediaKind, StegoTechnique};
    use bytes::Bytes;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Mock embedder that appends payload bytes to cover data.
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
            data.extend_from_slice(payload.as_bytes());
            Ok(CoverMedia {
                kind: cover.kind,
                data: Bytes::from(data),
                metadata: cover.metadata,
            })
        }
    }

    fn make_cover(size: usize) -> CoverMedia {
        CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(vec![0u8; size]),
            metadata: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn one_to_one_round_trip() -> TestResult {
        let distributor = DistributorImpl::new(b"test-hmac-key".to_vec());
        let payload = Payload::from_bytes(b"secret message".to_vec());
        let covers = vec![make_cover(128)];
        let result =
            distributor.distribute(&payload, &EmbeddingProfile::Standard, covers, &MockEmbedder)?;
        assert_eq!(result.len(), 1);
        // Cover data should be larger (128 + 14 bytes of payload)
        assert_eq!(
            result.first().ok_or("index out of bounds")?.data.len(),
            128 + 14
        );
        Ok(())
    }

    #[test]
    fn one_to_many_produces_correct_shard_count() -> TestResult {
        let covers: Vec<CoverMedia> = (0..8).map(|_| make_cover(256)).collect();
        let payload = Payload::from_bytes(vec![0xAB; 64]);

        // Manually use 1:N with 5 data + 3 parity = 8 total
        let pattern = DistributionPattern::OneToMany {
            data_shards: 5,
            parity_shards: 3,
        };
        validate_cover_count(&pattern, covers.len())?;

        let result =
            distribute_one_to_many(&payload, covers, &MockEmbedder, 5, 3, b"test-hmac-key")?;
        assert_eq!(result.len(), 8);
        // Each cover should have been modified (data extended)
        for cover in &result {
            assert!(cover.data.len() > 256);
        }
        Ok(())
    }

    #[test]
    fn many_to_one_embed_single_cover() -> TestResult {
        let distributor = DistributorImpl::new(b"test-hmac-key".to_vec());
        let payload = Payload::from_bytes(b"combined payload".to_vec());
        let covers = vec![make_cover(512)];
        let result =
            distributor.distribute(&payload, &EmbeddingProfile::Standard, covers, &MockEmbedder)?;
        assert_eq!(result.len(), 1);
        assert!(result.first().ok_or("empty result")?.data.len() > 512);
        Ok(())
    }

    #[test]
    fn many_to_many_replicate_mode() -> TestResult {
        let covers = vec![make_cover(256), make_cover(256), make_cover(256)];
        let payload = Payload::from_bytes(vec![0xCC; 30]);

        let result = distribute_many_to_many(
            &payload,
            covers,
            &MockEmbedder,
            crate::domain::types::ManyToManyMode::Replicate,
        )?;
        assert_eq!(result.len(), 3);
        // In replicate mode, each cover gets every chunk — all should be modified
        for cover in &result {
            assert!(cover.data.len() > 256);
        }
        Ok(())
    }

    #[test]
    fn insufficient_covers_returns_error() {
        let distributor = DistributorImpl::new(b"test-hmac-key".to_vec());
        let payload = Payload::from_bytes(b"test".to_vec());
        let covers: Vec<CoverMedia> = vec![];
        let result =
            distributor.distribute(&payload, &EmbeddingProfile::Standard, covers, &MockEmbedder);
        assert!(result.is_err());
    }

    #[test]
    fn pattern_from_profile_non_standard_preserves_distribution_topology() {
        let adaptive = EmbeddingProfile::Adaptive {
            max_detectability_db: 0.5,
        };
        let pattern = pattern_from_profile(&adaptive, 5, None);
        assert_eq!(
            pattern,
            DistributionPattern::OneToMany {
                data_shards: 4,
                parity_shards: 1,
            }
        );

        let corpus = EmbeddingProfile::CorpusBased;
        let pattern = pattern_from_profile(&corpus, 10, None);
        assert_eq!(pattern, DistributionPattern::OneToOne);
    }

    #[test]
    fn distribute_via_trait_many_to_many_replicate() -> TestResult {
        let covers = vec![make_cover(256), make_cover(256)];
        let payload = Payload::from_bytes(vec![0xAA; 20]);
        let result = distribute_many_to_many(
            &payload,
            covers,
            &MockEmbedder,
            crate::domain::types::ManyToManyMode::Stripe,
        )?;
        // Each chunk goes to one cover in stripe mode
        assert_eq!(result.len(), 2);
        for cover in &result {
            assert!(cover.data.len() > 256);
        }
        Ok(())
    }

    /// Embedder that always fails — for testing error propagation.
    struct FailEmbedder;

    impl EmbedTechnique for FailEmbedder {
        fn technique(&self) -> StegoTechnique {
            StegoTechnique::LsbImage
        }

        fn capacity(&self, _cover: &CoverMedia) -> Result<Capacity, StegoError> {
            Ok(Capacity {
                bytes: 0,
                technique: StegoTechnique::LsbImage,
            })
        }

        fn embed(&self, _cover: CoverMedia, _payload: &Payload) -> Result<CoverMedia, StegoError> {
            Err(StegoError::PayloadTooLarge {
                available: 0,
                needed: 1,
            })
        }
    }

    #[test]
    fn distribute_one_to_one_embed_failure() {
        let covers = vec![make_cover(64)];
        let payload = Payload::from_bytes(b"data".to_vec());
        let result = distribute_one_to_one(&payload, covers, &FailEmbedder);
        assert!(result.is_err());
    }

    #[test]
    fn distribute_one_to_many_embed_failure() {
        let covers: Vec<CoverMedia> = (0..4).map(|_| make_cover(256)).collect();
        let payload = Payload::from_bytes(vec![0xBB; 32]);
        let result =
            distribute_one_to_many(&payload, covers, &FailEmbedder, 3, 1, b"test-hmac-key");
        assert!(result.is_err());
    }

    #[test]
    fn distribute_many_to_many_embed_failure() {
        let covers = vec![make_cover(128), make_cover(128)];
        let payload = Payload::from_bytes(vec![0xCC; 20]);
        let result = distribute_many_to_many(
            &payload,
            covers,
            &FailEmbedder,
            crate::domain::types::ManyToManyMode::Replicate,
        );
        assert!(result.is_err());
    }

    #[test]
    fn distribute_default_impl() -> TestResult {
        let distributor = DistributorImpl::default();
        let payload = Payload::from_bytes(b"hello".to_vec());
        let covers = vec![make_cover(128)];
        let result =
            distributor.distribute(&payload, &EmbeddingProfile::Standard, covers, &MockEmbedder)?;
        assert_eq!(result.len(), 1);
        Ok(())
    }

    #[test]
    fn pack_unpack_multiple_payloads_for_many_to_one() -> TestResult {
        let payloads = vec![
            Payload::from_bytes(b"payload_a".to_vec()),
            Payload::from_bytes(b"payload_b".to_vec()),
            Payload::from_bytes(b"payload_c".to_vec()),
        ];
        let packed = pack_many_payloads(&payloads);
        let combined = Payload::from_bytes(packed);

        // Embed combined into single cover
        let covers = vec![make_cover(1024)];
        let result = distribute_one_to_one(&combined, covers, &MockEmbedder)?;
        assert_eq!(result.len(), 1);

        // The stego'd data contains original cover + packed payloads
        let stego_data = &result.first().ok_or("empty result")?.data;
        let embedded_portion = stego_data.get(1024..).ok_or("slice out of bounds")?;
        let unpacked = crate::domain::distribution::unpack_many_payloads(embedded_portion)?;
        assert_eq!(unpacked.len(), 3);
        assert_eq!(
            unpacked.first().ok_or("index out of bounds")?.as_bytes(),
            b"payload_a"
        );
        assert_eq!(
            unpacked.get(1).ok_or("index out of bounds")?.as_bytes(),
            b"payload_b"
        );
        assert_eq!(
            unpacked.get(2).ok_or("index out of bounds")?.as_bytes(),
            b"payload_c"
        );
        Ok(())
    }
}
