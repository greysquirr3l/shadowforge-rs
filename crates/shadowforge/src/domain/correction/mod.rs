//! Reed-Solomon K-of-N erasure coding with HMAC integrity.
//!
//! All functions are pure — no I/O, no file system, no network.

use bytes::Bytes;
use hmac::{Hmac, Mac};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::Sha256;

use crate::domain::errors::CorrectionError;
use crate::domain::types::Shard;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA-256 tag for a shard.
///
/// Tag covers: `index || total || data`
fn compute_hmac_tag(
    hmac_key: &[u8],
    index: u8,
    total: u8,
    data: &[u8],
) -> Result<[u8; 32], CorrectionError> {
    let mut mac =
        HmacSha256::new_from_slice(hmac_key).map_err(|_| CorrectionError::InvalidParameters {
            reason: "invalid HMAC key length".into(),
        })?;
    mac.update(&[index]);
    mac.update(&[total]);
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Verify HMAC tag for a shard.
///
/// Returns `true` if the tag is valid.
fn verify_hmac_tag(hmac_key: &[u8], shard: &Shard) -> Result<bool, CorrectionError> {
    use subtle::ConstantTimeEq;

    let expected = compute_hmac_tag(hmac_key, shard.index, shard.total, &shard.data)?;
    Ok(expected.ct_eq(&shard.hmac_tag).into())
}

/// Encode data into Reed-Solomon shards with HMAC tags.
///
/// # Errors
/// Returns [`CorrectionError::InvalidParameters`] if shard counts are invalid,
/// or [`CorrectionError::ReedSolomonError`] if encoding fails.
pub fn encode_shards(
    data: &[u8],
    data_shards: u8,
    parity_shards: u8,
    hmac_key: &[u8],
) -> Result<Vec<Shard>, CorrectionError> {
    if data_shards == 0 {
        return Err(CorrectionError::InvalidParameters {
            reason: "data_shards must be > 0".into(),
        });
    }
    if parity_shards == 0 {
        return Err(CorrectionError::InvalidParameters {
            reason: "parity_shards must be > 0".into(),
        });
    }

    let total_shards = data_shards.strict_add(parity_shards);
    let shard_size = (data
        .len()
        .strict_add(usize::from(data_shards).strict_sub(1)))
        / usize::from(data_shards);

    // Pad data to fit evenly into data_shards
    let total_size = shard_size.strict_mul(usize::from(data_shards));
    let mut padded = vec![0u8; total_size];
    padded
        .get_mut(..data.len())
        .ok_or_else(|| CorrectionError::InvalidParameters {
            reason: "data length exceeds padded buffer".into(),
        })?
        .copy_from_slice(data);

    // Create Reed-Solomon encoder
    let rs =
        ReedSolomon::new(usize::from(data_shards), usize::from(parity_shards)).map_err(|e| {
            CorrectionError::ReedSolomonError {
                reason: e.to_string(),
            }
        })?;

    // Split into chunks
    let mut chunks: Vec<Vec<u8>> = padded.chunks(shard_size).map(<[u8]>::to_vec).collect();

    // Add parity shards
    chunks.resize(usize::from(total_shards), vec![0u8; shard_size]);

    // Encode
    rs.encode(&mut chunks)
        .map_err(|e| CorrectionError::ReedSolomonError {
            reason: e.to_string(),
        })?;

    // Create shards with HMAC tags
    let shards = chunks
        .into_iter()
        .enumerate()
        .map(|(i, data)| {
            #[expect(clippy::cast_possible_truncation, reason = "total_shards is u8")]
            let index = i as u8;
            let hmac_tag = compute_hmac_tag(hmac_key, index, total_shards, &data)?;
            Ok(Shard {
                index,
                total: total_shards,
                data,
                hmac_tag,
            })
        })
        .collect::<Result<Vec<Shard>, CorrectionError>>()?;

    Ok(shards)
}

/// Decode Reed-Solomon shards back to original data.
///
/// Accepts partial shard sets (some may be `None`). Requires at least
/// `data_shards` valid shards with passing HMAC tags.
///
/// # Errors
/// Returns [`CorrectionError::InsufficientShards`] if not enough valid shards,
/// [`CorrectionError::HmacMismatch`] if HMAC verification fails, or
/// [`CorrectionError::ReedSolomonError`] if decoding fails.
pub fn decode_shards(
    shards: &[Option<Shard>],
    data_shards: u8,
    parity_shards: u8,
    hmac_key: &[u8],
    original_len: usize,
) -> Result<Bytes, CorrectionError> {
    let total_shards = data_shards.strict_add(parity_shards);

    if shards.len() != usize::from(total_shards) {
        return Err(CorrectionError::InvalidParameters {
            reason: format!("expected {} shards, got {}", total_shards, shards.len()),
        });
    }

    // Verify HMAC tags for all present shards
    for shard in shards.iter().flatten() {
        if !verify_hmac_tag(hmac_key, shard)? {
            return Err(CorrectionError::HmacMismatch { index: shard.index });
        }
    }

    // Count valid shards
    let valid_count = shards.iter().filter(|s| s.is_some()).count();
    if valid_count < usize::from(data_shards) {
        return Err(CorrectionError::InsufficientShards {
            needed: usize::from(data_shards),
            available: valid_count,
        });
    }

    // Create Reed-Solomon decoder
    let rs =
        ReedSolomon::new(usize::from(data_shards), usize::from(parity_shards)).map_err(|e| {
            CorrectionError::ReedSolomonError {
                reason: e.to_string(),
            }
        })?;

    // Convert to Option<Vec<u8>> for RS decoder
    let mut chunks: Vec<Option<Vec<u8>>> = shards
        .iter()
        .map(|opt| opt.as_ref().map(|s| s.data.clone()))
        .collect();

    // Decode
    rs.reconstruct(&mut chunks)
        .map_err(|e| CorrectionError::ReedSolomonError {
            reason: e.to_string(),
        })?;

    // Extract data shards
    let mut recovered = Vec::new();
    for chunk in chunks.iter().take(usize::from(data_shards)).flatten() {
        recovered.extend_from_slice(chunk);
    }

    // Trim to original length
    recovered.truncate(original_len);

    Ok(Bytes::from(recovered))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const HMAC_KEY: &[u8] = b"test_hmac_key_32_bytes_long_!!!";

    #[test]
    fn test_encode_decode_roundtrip() -> TestResult {
        let data = b"The quick brown fox jumps over the lazy dog";
        let data_shards = 10;
        let parity_shards = 5;

        let shards = encode_shards(data, data_shards, parity_shards, HMAC_KEY)?;
        assert_eq!(shards.len(), 15);

        // Convert to Option<Shard>
        let opt_shards: Vec<Option<Shard>> = shards.into_iter().map(Some).collect();

        let recovered = decode_shards(
            &opt_shards,
            data_shards,
            parity_shards,
            HMAC_KEY,
            data.len(),
        )?;

        assert_eq!(recovered.as_ref(), data);
        Ok(())
    }

    #[test]
    fn test_decode_with_missing_shards() -> TestResult {
        let data = b"The quick brown fox jumps over the lazy dog";
        let data_shards = 10;
        let parity_shards = 5;

        let shards = encode_shards(data, data_shards, parity_shards, HMAC_KEY)?;

        // Drop 5 shards (any 5)
        let mut opt_shards: Vec<Option<Shard>> = shards.into_iter().map(Some).collect();
        *opt_shards.get_mut(0).ok_or("out of bounds")? = None;
        *opt_shards.get_mut(3).ok_or("out of bounds")? = None;
        *opt_shards.get_mut(7).ok_or("out of bounds")? = None;
        *opt_shards.get_mut(10).ok_or("out of bounds")? = None;
        *opt_shards.get_mut(13).ok_or("out of bounds")? = None;

        let recovered = decode_shards(
            &opt_shards,
            data_shards,
            parity_shards,
            HMAC_KEY,
            data.len(),
        )?;

        assert_eq!(recovered.as_ref(), data);
        Ok(())
    }

    #[test]
    fn test_decode_insufficient_shards() -> TestResult {
        let data = b"test data";
        let data_shards = 10;
        let parity_shards = 5;

        let shards = encode_shards(data, data_shards, parity_shards, HMAC_KEY)?;

        // Drop 6 shards (too many)
        let mut opt_shards: Vec<Option<Shard>> = shards.into_iter().map(Some).collect();
        for i in 0..6 {
            *opt_shards.get_mut(i).ok_or("out of bounds")? = None;
        }

        let result = decode_shards(
            &opt_shards,
            data_shards,
            parity_shards,
            HMAC_KEY,
            data.len(),
        );
        assert!(matches!(
            result,
            Err(CorrectionError::InsufficientShards { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_decode_hmac_mismatch() -> TestResult {
        let data = b"test data";
        let data_shards = 10;
        let parity_shards = 5;

        let mut shards = encode_shards(data, data_shards, parity_shards, HMAC_KEY)?;

        // Tamper with one shard's data
        let shard = shards.get_mut(0).ok_or("missing shard 0")?;
        *shard.data.first_mut().ok_or("empty shard data")? ^= 0xFF;

        let opt_shards: Vec<Option<Shard>> = shards.into_iter().map(Some).collect();

        let result = decode_shards(
            &opt_shards,
            data_shards,
            parity_shards,
            HMAC_KEY,
            data.len(),
        );
        assert!(matches!(result, Err(CorrectionError::HmacMismatch { .. })));
        Ok(())
    }

    #[test]
    fn test_encode_zero_data_shards() {
        let data = b"test";
        let result = encode_shards(data, 0, 5, HMAC_KEY);
        assert!(matches!(
            result,
            Err(CorrectionError::InvalidParameters { .. })
        ));
    }

    #[test]
    fn test_encode_zero_parity_shards() {
        let data = b"test";
        let result = encode_shards(data, 10, 0, HMAC_KEY);
        assert!(matches!(
            result,
            Err(CorrectionError::InvalidParameters { .. })
        ));
    }
}
