//! Adapter implementing the [`Reconstructor`] port for K-of-N shard
//! reassembly with full verification chain.

use crate::domain::correction::decode_shards;
use crate::domain::errors::ReconstructionError;
use crate::domain::ports::{ExtractTechnique, Reconstructor};
use crate::domain::reconstruction::{
    arrange_shards, count_present, deserialize_shard, validate_shard_count,
};
use crate::domain::types::{CoverMedia, Payload};

/// Concrete [`Reconstructor`] implementation.
///
/// Reconstruction chain:
/// 1. Extract shard data from each stego cover
/// 2. Arrange shards by index into slots
/// 3. Validate minimum shard count (K of N)
/// 4. RS-decode to recover original payload
pub struct ReconstructorImpl {
    /// Number of data shards (K).
    data_shards: u8,
    /// Number of parity shards (M).
    parity_shards: u8,
    /// HMAC key for shard verification.
    hmac_key: Vec<u8>,
    /// Original payload length for RS trim.
    original_len: usize,
}

impl ReconstructorImpl {
    /// Create a new reconstructor with the given shard parameters.
    #[must_use]
    pub const fn new(
        data_shards: u8,
        parity_shards: u8,
        hmac_key: Vec<u8>,
        original_len: usize,
    ) -> Self {
        Self {
            data_shards,
            parity_shards,
            hmac_key,
            original_len,
        }
    }
}

impl Reconstructor for ReconstructorImpl {
    fn reconstruct(
        &self,
        covers: Vec<CoverMedia>,
        extractor: &dyn ExtractTechnique,
        progress_cb: &dyn Fn(usize, usize),
    ) -> Result<Payload, ReconstructionError> {
        let total = covers.len();
        let total_shards = self.data_shards.strict_add(self.parity_shards);

        // Step 1: Extract shard data from each cover
        let mut shards = Vec::with_capacity(total);
        for (i, cover) in covers.into_iter().enumerate() {
            match extractor.extract(&cover) {
                Ok(payload) => {
                    // Deserialize from the embedded binary format
                    if let Some(shard) = deserialize_shard(payload.as_bytes()) {
                        shards.push(shard);
                    } else {
                        tracing::warn!(
                            cover_index = i,
                            "could not deserialize shard, treating as missing"
                        );
                    }
                }
                Err(e) => {
                    // Treat extraction failure as missing shard
                    // (within parity budget, reconstruction may still succeed)
                    tracing::warn!(cover_index = i, error = %e, "extraction failed, treating as missing shard");
                }
            }
            progress_cb(i.strict_add(1), total);
        }

        // Step 2: Arrange by index
        let slots = arrange_shards(shards, total_shards);
        let present = count_present(&slots);

        // Step 3: Validate minimum count
        validate_shard_count(present, usize::from(self.data_shards))?;

        // Step 4: RS-decode
        let recovered = decode_shards(
            &slots,
            self.data_shards,
            self.parity_shards,
            &self.hmac_key,
            self.original_len,
        )
        .map_err(|source| ReconstructionError::CorrectionFailed { source })?;

        Ok(Payload::from_bytes(recovered.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::correction::encode_shards;
    use crate::domain::errors::StegoError;
    use crate::domain::ports::EmbedTechnique;
    use crate::domain::reconstruction::serialize_shard;
    use crate::domain::types::{Capacity, CoverMedia, CoverMediaKind, StegoTechnique};
    use bytes::Bytes;
    use std::cell::Cell;

    /// Mock embedder: prepends a 4-byte length header then payload.
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

    /// Mock extractor: reads length-prefixed payload after cover prefix.
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
            let len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            let start = offset + 4;
            if start + len > data.len() {
                return Err(StegoError::NoPayloadFound);
            }
            Ok(Payload::from_bytes(data[start..start + len].to_vec()))
        }
    }

    fn make_cover(size: usize) -> CoverMedia {
        CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(vec![0u8; size]),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Helper: encode payload into shards, embed each in a cover.
    fn distribute_and_get_covers(
        payload: &[u8],
        data_shards: u8,
        parity_shards: u8,
        hmac_key: &[u8],
        cover_size: usize,
    ) -> Vec<CoverMedia> {
        let shards = encode_shards(payload, data_shards, parity_shards, hmac_key)
            .expect("encoding should succeed");
        let embedder = MockEmbedder;
        shards
            .iter()
            .map(|shard| {
                let cover = make_cover(cover_size);
                // Embed the full serialized shard (index + total + hmac + data)
                let serialized = serialize_shard(shard);
                let shard_payload = Payload::from_bytes(serialized);
                embedder
                    .embed(cover, &shard_payload)
                    .expect("embed should succeed")
            })
            .collect()
    }

    #[test]
    fn full_recovery_all_shards_present() {
        let original = b"hello reconstruction world!";
        let hmac_key = b"test-hmac-key";
        let covers = distribute_and_get_covers(original, 3, 2, hmac_key, 128);
        assert_eq!(covers.len(), 5);

        let reconstructor = ReconstructorImpl::new(3, 2, hmac_key.to_vec(), original.len());
        let extractor = MockExtractor {
            cover_prefix_len: 128,
        };
        let progress_calls = Cell::new(0usize);
        let result = reconstructor
            .reconstruct(covers, &extractor, &|_done, _total| {
                progress_calls.set(progress_calls.get().strict_add(1));
            })
            .expect("reconstruction should succeed");

        assert_eq!(result.as_bytes(), original);
        assert_eq!(progress_calls.get(), 5);
    }

    #[test]
    fn partial_recovery_minimum_shards() {
        let original = b"partial recovery test payload";
        let hmac_key = b"test-hmac-key";
        let mut covers = distribute_and_get_covers(original, 3, 2, hmac_key, 128);
        assert_eq!(covers.len(), 5);

        // Drop 2 parity shards (keep exactly data_shards = 3)
        covers.remove(4);
        covers.remove(3);

        let reconstructor = ReconstructorImpl::new(3, 2, hmac_key.to_vec(), original.len());
        let extractor = MockExtractor {
            cover_prefix_len: 128,
        };
        let result = reconstructor
            .reconstruct(covers, &extractor, &|_, _| {})
            .expect("partial reconstruction should succeed");

        assert_eq!(result.as_bytes(), original);
    }

    #[test]
    fn insufficient_shards_returns_error() {
        let original = b"not enough shards";
        let hmac_key = b"test-hmac-key";
        let mut covers = distribute_and_get_covers(original, 3, 2, hmac_key, 128);

        // Drop 3 shards (only 2 remain, but need 3)
        covers.remove(4);
        covers.remove(3);
        covers.remove(2);

        let reconstructor = ReconstructorImpl::new(3, 2, hmac_key.to_vec(), original.len());
        let extractor = MockExtractor {
            cover_prefix_len: 128,
        };
        let result = reconstructor.reconstruct(covers, &extractor, &|_, _| {});

        assert!(result.is_err());
    }

    #[test]
    fn progress_callback_called_correctly() {
        let original = b"track progress";
        let hmac_key = b"test-hmac-key";
        let covers = distribute_and_get_covers(original, 2, 1, hmac_key, 64);
        let total_covers = covers.len();

        let reconstructor = ReconstructorImpl::new(2, 1, hmac_key.to_vec(), original.len());
        let extractor = MockExtractor {
            cover_prefix_len: 64,
        };

        let progress_log = std::cell::RefCell::new(Vec::new());
        let result = reconstructor
            .reconstruct(covers, &extractor, &|done, total| {
                progress_log.borrow_mut().push((done, total));
            })
            .expect("reconstruction should succeed");

        assert_eq!(result.as_bytes(), original);
        let log = progress_log.borrow();
        assert_eq!(log.len(), total_covers);
        for (i, &(done, total)) in log.iter().enumerate() {
            assert_eq!(done, i + 1);
            assert_eq!(total, total_covers);
        }
    }
}
