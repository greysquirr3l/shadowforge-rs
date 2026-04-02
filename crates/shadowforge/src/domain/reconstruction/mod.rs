//! K-of-N shard reassembly with manifest verification.
//!
//! Pure domain logic — no I/O, no file system, no async runtime.

use crate::domain::errors::ReconstructionError;
use crate::domain::types::Shard;

/// Validate that enough shards are present for reconstruction.
///
/// # Errors
/// Returns [`ReconstructionError::InsufficientCovers`] if `available < needed`.
pub const fn validate_shard_count(
    available: usize,
    needed: usize,
) -> Result<(), ReconstructionError> {
    if available < needed {
        return Err(ReconstructionError::InsufficientCovers {
            needed,
            got: available,
        });
    }
    Ok(())
}

/// Reorder extracted shard data into shard slots based on embedded index.
///
/// Returns a `Vec<Option<Shard>>` of length `total_shards`, placing each
/// shard at its declared index position. Duplicate indices are ignored.
#[must_use]
pub fn arrange_shards(shards: Vec<Shard>, total_shards: u8) -> Vec<Option<Shard>> {
    let mut slots: Vec<Option<Shard>> = (0..usize::from(total_shards)).map(|_| None).collect();
    for shard in shards {
        let idx = usize::from(shard.index);
        if let Some(slot @ None) = slots.get_mut(idx) {
            *slot = Some(shard);
        }
    }
    slots
}

/// Count how many shards are present (non-None) in a slot array.
#[must_use]
pub fn count_present(slots: &[Option<Shard>]) -> usize {
    slots.iter().filter(|s| s.is_some()).count()
}

/// Serialize a shard to binary: `[index:1][total:1][hmac:32][data_len:4][data:N]`.
#[must_use]
pub fn serialize_shard(shard: &Shard) -> Vec<u8> {
    let data_len = shard.data.len();
    let mut buf = Vec::with_capacity(1 + 1 + 32 + 4 + data_len);
    buf.push(shard.index);
    buf.push(shard.total);
    buf.extend_from_slice(&shard.hmac_tag);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "shard data len bounded below u32::MAX"
    )]
    let len = data_len as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&shard.data);
    buf
}

/// Deserialize a shard from binary produced by [`serialize_shard`].
///
/// # Errors
/// Returns `None` if the buffer is too short or corrupted.
#[must_use]
pub fn deserialize_shard(data: &[u8]) -> Option<Shard> {
    // Minimum: index(1) + total(1) + hmac(32) + data_len(4) = 38
    let index = *data.first()?;
    let total = *data.get(1)?;
    let mut hmac_tag = [0u8; 32];
    hmac_tag.copy_from_slice(data.get(2..34)?);
    let len_bytes: [u8; 4] = data.get(34..38)?.try_into().ok()?;
    let data_len = u32::from_le_bytes(len_bytes) as usize;
    let shard_data = data.get(38..38_usize.strict_add(data_len))?.to_vec();
    Some(Shard {
        index,
        total,
        data: shard_data,
        hmac_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn make_shard(index: u8, total: u8, data: &[u8]) -> Shard {
        Shard {
            index,
            total,
            data: data.to_vec(),
            hmac_tag: [0u8; 32],
        }
    }

    #[test]
    fn validate_shard_count_sufficient() {
        assert!(validate_shard_count(5, 3).is_ok());
        assert!(validate_shard_count(3, 3).is_ok());
    }

    #[test]
    fn validate_shard_count_insufficient() {
        let err = validate_shard_count(2, 3);
        assert!(err.is_err());
    }

    #[test]
    fn arrange_shards_correct_placement() -> TestResult {
        let shards = vec![
            make_shard(2, 4, b"c"),
            make_shard(0, 4, b"a"),
            make_shard(3, 4, b"d"),
        ];
        let slots = arrange_shards(shards, 4);
        assert_eq!(slots.len(), 4);
        assert!(slots.first().and_then(Option::as_ref).is_some());
        assert!(slots.get(1).and_then(Option::as_ref).is_none());
        assert!(slots.get(2).and_then(Option::as_ref).is_some());
        assert!(slots.get(3).and_then(Option::as_ref).is_some());
        assert_eq!(
            slots
                .first()
                .and_then(Option::as_ref)
                .ok_or("missing slot 0")?
                .data,
            b"a"
        );
        assert_eq!(
            slots
                .get(2)
                .and_then(Option::as_ref)
                .ok_or("missing slot 2")?
                .data,
            b"c"
        );
        Ok(())
    }

    #[test]
    fn arrange_shards_duplicate_index_ignored() -> TestResult {
        let shards = vec![make_shard(0, 2, b"first"), make_shard(0, 2, b"second")];
        let slots = arrange_shards(shards, 2);
        assert_eq!(
            slots
                .first()
                .and_then(Option::as_ref)
                .ok_or("missing slot 0")?
                .data,
            b"first"
        );
        Ok(())
    }

    #[test]
    fn count_present_correct() {
        let slots = vec![
            Some(make_shard(0, 3, b"a")),
            None,
            Some(make_shard(2, 3, b"c")),
        ];
        assert_eq!(count_present(&slots), 2);
    }
}
