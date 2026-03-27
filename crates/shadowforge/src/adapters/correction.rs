//! Reed-Solomon error correction adapter.

use bytes::Bytes;

use crate::domain::correction::{decode_shards, encode_shards};
use crate::domain::errors::CorrectionError;
use crate::domain::ports::ErrorCorrector;
use crate::domain::types::Shard;

/// Reed-Solomon error correction adapter with HMAC-tagged shards.
///
/// Implements the [`ErrorCorrector`] port using the `reed-solomon-erasure` crate.
/// Each shard is tagged with HMAC-SHA-256 for integrity verification.
#[derive(Debug)]
pub struct RsErrorCorrector {
    /// HMAC key for shard integrity tags.
    hmac_key: Vec<u8>,
}

impl RsErrorCorrector {
    /// Create a new Reed-Solomon error corrector with the given HMAC key.
    ///
    /// # Panics
    /// Panics if `hmac_key` is empty.
    #[must_use]
    pub fn new(hmac_key: Vec<u8>) -> Self {
        assert!(!hmac_key.is_empty(), "HMAC key must not be empty");
        Self { hmac_key }
    }
}

impl ErrorCorrector for RsErrorCorrector {
    fn encode(
        &self,
        data: &[u8],
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Vec<Shard>, CorrectionError> {
        encode_shards(data, data_shards, parity_shards, &self.hmac_key)
    }

    fn decode(
        &self,
        shards: &[Option<Shard>],
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Bytes, CorrectionError> {
        // Calculate original data length from the first available shard
        let first_shard = shards
            .iter()
            .find_map(|opt| opt.as_ref())
            .ok_or_else(|| CorrectionError::InsufficientShards {
                needed: usize::from(data_shards),
                available: 0,
            })?;

        // Original length is encoded in the first data shard's metadata
        // For now, we'll reconstruct all data and let the caller handle trimming
        // In a real implementation, this would be in a shard metadata field
        let shard_size = first_shard.data.len();
        let total_data_size = shard_size.strict_mul(usize::from(data_shards));

        decode_shards(
            shards,
            data_shards,
            parity_shards,
            &self.hmac_key,
            total_data_size,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rs_error_corrector_roundtrip() {
        let hmac_key = b"test_key_32_bytes_long_padding!!".to_vec();
        let corrector = RsErrorCorrector::new(hmac_key);

        let data = b"The quick brown fox jumps over the lazy dog";
        let shards = corrector.encode(data, 10, 5).expect("encode");

        let opt_shards: Vec<Option<Shard>> = shards.into_iter().map(Some).collect();
        let recovered = corrector.decode(&opt_shards, 10, 5).expect("decode");

        // Recovered data may be padded, so check prefix
        assert!(recovered.starts_with(data));
    }

    #[test]
    fn test_rs_error_corrector_with_missing_shards() {
        let hmac_key = b"test_key_32_bytes_long_padding!!".to_vec();
        let corrector = RsErrorCorrector::new(hmac_key);

        let data = b"The quick brown fox jumps over the lazy dog";
        let shards = corrector.encode(data, 10, 5).expect("encode");

        // Drop 5 shards
        let mut opt_shards: Vec<Option<Shard>> = shards.into_iter().map(Some).collect();
        opt_shards[0] = None;
        opt_shards[3] = None;
        opt_shards[7] = None;
        opt_shards[10] = None;
        opt_shards[13] = None;

        let recovered = corrector.decode(&opt_shards, 10, 5).expect("decode");
        assert!(recovered.starts_with(data));
    }

    #[test]
    fn test_rs_error_corrector_insufficient_shards() {
        let hmac_key = b"test_key_32_bytes_long_padding!!".to_vec();
        let corrector = RsErrorCorrector::new(hmac_key);

        let data = b"test data";
        let shards = corrector.encode(data, 10, 5).expect("encode");

        // Drop 6 shards (too many)
        let mut opt_shards: Vec<Option<Shard>> = shards.into_iter().map(Some).collect();
        for i in 0..6 {
            opt_shards[i] = None;
        }

        let result = corrector.decode(&opt_shards, 10, 5);
        assert!(matches!(
            result,
            Err(CorrectionError::InsufficientShards { .. })
        ));
    }
}
