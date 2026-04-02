//! Adapter implementing the [`Distributor`] port for all four distribution
//! patterns: 1:1, 1:N, N:1, N:M.

use crate::domain::distribution::{assign_many_to_many, assign_one_to_many, validate_cover_count};
use crate::domain::errors::DistributionError;
use crate::domain::ports::{Distributor, EmbedTechnique};
use crate::domain::types::{CoverMedia, DistributionPattern, EmbeddingProfile, Payload};

/// Concrete [`Distributor`] implementation.
pub struct DistributorImpl;

impl Default for DistributorImpl {
    fn default() -> Self {
        Self
    }
}

impl DistributorImpl {
    /// Create a new distributor.
    #[must_use]
    pub const fn new() -> Self {
        Self
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
        let pattern = pattern_from_profile(profile, covers.len());
        validate_cover_count(&pattern, covers.len())?;

        match pattern {
            DistributionPattern::OneToOne => distribute_one_to_one(payload, covers, embedder),
            DistributionPattern::OneToMany {
                data_shards,
                parity_shards,
            } => distribute_one_to_many(payload, covers, embedder, data_shards, parity_shards),
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
fn pattern_from_profile(profile: &EmbeddingProfile, cover_count: usize) -> DistributionPattern {
    // Standard profiles default to OneToOne for single cover, OneToMany otherwise
    match profile {
        EmbeddingProfile::Standard => {
            if cover_count <= 1 {
                DistributionPattern::OneToOne
            } else {
                // Default: split evenly across covers with 1 parity shard
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "cover_count bounded by caller"
                )]
                let data = (cover_count.saturating_sub(1)) as u8;
                let parity = 1u8;
                DistributionPattern::OneToMany {
                    data_shards: data.max(1),
                    parity_shards: parity,
                }
            }
        }
        _ => DistributionPattern::OneToOne,
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
) -> Result<Vec<CoverMedia>, DistributionError> {
    use crate::domain::correction::encode_shards;

    let hmac_key = b"distribution-hmac-key"; // TODO(T33): derive from session key
    let shards = encode_shards(payload.as_bytes(), data_shards, parity_shards, hmac_key)
        .map_err(|source| DistributionError::CorrectionFailed { source })?;

    let assignments = assign_one_to_many(shards.len(), covers.len());
    let mut result = covers;

    for (shard_idx, cover_idx) in assignments {
        let shard_payload = Payload::from_bytes(shards[shard_idx].data.clone());
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
        if shard_idx >= chunks.len() {
            break;
        }
        for &cover_idx in cover_indices {
            let cover = result.remove(cover_idx);
            let stego = embedder
                .embed(cover, &chunks[shard_idx])
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
    fn one_to_one_round_trip() {
        let distributor = DistributorImpl::new();
        let payload = Payload::from_bytes(b"secret message".to_vec());
        let covers = vec![make_cover(128)];
        let result = distributor
            .distribute(&payload, &EmbeddingProfile::Standard, covers, &MockEmbedder)
            .expect("distribute should succeed");
        assert_eq!(result.len(), 1);
        // Cover data should be larger (128 + 14 bytes of payload)
        assert_eq!(result[0].data.len(), 128 + 14);
    }

    #[test]
    fn one_to_many_produces_correct_shard_count() {
        let covers: Vec<CoverMedia> = (0..8).map(|_| make_cover(256)).collect();
        let payload = Payload::from_bytes(vec![0xAB; 64]);

        // Manually use 1:N with 5 data + 3 parity = 8 total
        let pattern = DistributionPattern::OneToMany {
            data_shards: 5,
            parity_shards: 3,
        };
        validate_cover_count(&pattern, covers.len()).expect("should be valid");

        let result = distribute_one_to_many(&payload, covers, &MockEmbedder, 5, 3)
            .expect("distribute should succeed");
        assert_eq!(result.len(), 8);
        // Each cover should have been modified (data extended)
        for cover in &result {
            assert!(cover.data.len() > 256);
        }
    }

    #[test]
    fn many_to_one_embed_single_cover() {
        let distributor = DistributorImpl::new();
        let payload = Payload::from_bytes(b"combined payload".to_vec());
        let covers = vec![make_cover(512)];
        let result = distributor
            .distribute(&payload, &EmbeddingProfile::Standard, covers, &MockEmbedder)
            .expect("distribute should succeed");
        assert_eq!(result.len(), 1);
        assert!(result[0].data.len() > 512);
    }

    #[test]
    fn many_to_many_replicate_mode() {
        let covers = vec![make_cover(256), make_cover(256), make_cover(256)];
        let payload = Payload::from_bytes(vec![0xCC; 30]);

        let result = distribute_many_to_many(
            &payload,
            covers,
            &MockEmbedder,
            crate::domain::types::ManyToManyMode::Replicate,
        )
        .expect("distribute should succeed");
        assert_eq!(result.len(), 3);
        // In replicate mode, each cover gets every chunk — all should be modified
        for cover in &result {
            assert!(cover.data.len() > 256);
        }
    }

    #[test]
    fn insufficient_covers_returns_error() {
        let distributor = DistributorImpl::new();
        let payload = Payload::from_bytes(b"test".to_vec());
        let covers: Vec<CoverMedia> = vec![];
        let result =
            distributor.distribute(&payload, &EmbeddingProfile::Standard, covers, &MockEmbedder);
        assert!(result.is_err());
    }

    #[test]
    fn pack_unpack_multiple_payloads_for_many_to_one() {
        let payloads = vec![
            Payload::from_bytes(b"payload_a".to_vec()),
            Payload::from_bytes(b"payload_b".to_vec()),
            Payload::from_bytes(b"payload_c".to_vec()),
        ];
        let packed = pack_many_payloads(&payloads);
        let combined = Payload::from_bytes(packed.clone());

        // Embed combined into single cover
        let covers = vec![make_cover(1024)];
        let result =
            distribute_one_to_one(&combined, covers, &MockEmbedder).expect("embed should succeed");
        assert_eq!(result.len(), 1);

        // The stego'd data contains original cover + packed payloads
        let stego_data = &result[0].data;
        let embedded_portion = &stego_data[1024..];
        let unpacked = crate::domain::distribution::unpack_many_payloads(embedded_portion)
            .expect("unpack should succeed");
        assert_eq!(unpacked.len(), 3);
        assert_eq!(unpacked[0].as_bytes(), b"payload_a");
        assert_eq!(unpacked[1].as_bytes(), b"payload_b");
        assert_eq!(unpacked[2].as_bytes(), b"payload_c");
    }
}
