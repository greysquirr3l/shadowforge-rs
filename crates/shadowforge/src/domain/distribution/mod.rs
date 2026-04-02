//! Four distribution patterns: 1:1, 1:N, N:1, N:M.
//!
//! Pure domain logic — no I/O, no file system, no async runtime.
//! The adapter layer is responsible for parallel execution (rayon).

use crate::domain::errors::DistributionError;
use crate::domain::types::{DistributionPattern, ManyToManyMode, Payload};

/// Validate that the cover count satisfies the distribution pattern.
///
/// # Errors
/// Returns [`DistributionError::InsufficientCovers`] if too few covers.
pub const fn validate_cover_count(
    pattern: &DistributionPattern,
    cover_count: usize,
) -> Result<(), DistributionError> {
    let needed = minimum_covers(pattern);
    if cover_count < needed {
        return Err(DistributionError::InsufficientCovers {
            needed,
            got: cover_count,
        });
    }
    Ok(())
}

/// Minimum number of covers required for a given pattern.
#[must_use]
pub const fn minimum_covers(pattern: &DistributionPattern) -> usize {
    match pattern {
        DistributionPattern::OneToOne | DistributionPattern::ManyToOne => 1,
        DistributionPattern::OneToMany {
            data_shards,
            parity_shards,
        } => {
            // Need at least data_shards + parity_shards covers
            (*data_shards as usize).strict_add(*parity_shards as usize)
        }
        DistributionPattern::ManyToMany { .. } => 2,
    }
}

/// Assign shards to covers for 1:N distribution.
///
/// Returns a `Vec<(shard_index, cover_index)>` mapping.
#[must_use]
pub fn assign_one_to_many(shard_count: usize, cover_count: usize) -> Vec<(usize, usize)> {
    (0..shard_count).map(|i| (i, i % cover_count)).collect()
}

/// Assign shards to covers for M:N (many-to-many) distribution.
///
/// Returns a `Vec<Vec<usize>>` where outer index = shard and inner = cover indices.
#[must_use]
pub fn assign_many_to_many(
    mode: ManyToManyMode,
    shard_count: usize,
    cover_count: usize,
    seed: u64,
) -> Vec<Vec<usize>> {
    match mode {
        ManyToManyMode::Replicate => {
            // Every shard goes to every cover
            let all_covers: Vec<usize> = (0..cover_count).collect();
            (0..shard_count).map(|_| all_covers.clone()).collect()
        }
        ManyToManyMode::Stripe => {
            // Round-robin stripe across covers
            (0..shard_count).map(|i| vec![i % cover_count]).collect()
        }
        ManyToManyMode::Diagonal => {
            // Diagonal assignment across the matrix
            (0..shard_count)
                .map(|i| {
                    let primary = i % cover_count;
                    let secondary = (i.strict_add(1)) % cover_count;
                    if primary == secondary {
                        vec![primary]
                    } else {
                        vec![primary, secondary]
                    }
                })
                .collect()
        }
        ManyToManyMode::Random => {
            // Deterministic pseudo-random assignment using LCG
            let mut state = seed;
            (0..shard_count)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    let idx = (state >> 33) as usize % cover_count;
                    vec![idx]
                })
                .collect()
        }
    }
}

/// Build a concatenated multi-payload with length-prefix manifest for N:1.
///
/// Format: `[count:4][len_0:4][data_0][len_1:4][data_1]...`
#[must_use]
pub fn pack_many_payloads(payloads: &[Payload]) -> Vec<u8> {
    let mut buf = Vec::new();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "payload count bounded well below u32::MAX"
    )]
    let count = payloads.len() as u32;
    buf.extend_from_slice(&count.to_le_bytes());
    for p in payloads {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "individual payload size bounded below u32::MAX"
        )]
        let len = p.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(p.as_bytes());
    }
    buf
}

/// Unpack a multi-payload buffer produced by [`pack_many_payloads`].
///
/// # Errors
/// Returns [`DistributionError::InsufficientCovers`] (repurposed) if the
/// buffer is truncated.
pub fn unpack_many_payloads(data: &[u8]) -> Result<Vec<Payload>, DistributionError> {
    if data.len() < 4 {
        return Err(DistributionError::InsufficientCovers {
            needed: 4,
            got: data.len(),
        });
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut offset: usize = 4;
    let mut payloads = Vec::with_capacity(count);
    for _ in 0..count {
        if offset.strict_add(4) > data.len() {
            return Err(DistributionError::InsufficientCovers {
                needed: offset.strict_add(4),
                got: data.len(),
            });
        }
        let len = u32::from_le_bytes([
            data[offset],
            data[offset.strict_add(1)],
            data[offset.strict_add(2)],
            data[offset.strict_add(3)],
        ]) as usize;
        offset = offset.strict_add(4);
        if offset.strict_add(len) > data.len() {
            return Err(DistributionError::InsufficientCovers {
                needed: offset.strict_add(len),
                got: data.len(),
            });
        }
        payloads.push(Payload::from_bytes(
            data[offset..offset.strict_add(len)].to_vec(),
        ));
        offset = offset.strict_add(len);
    }
    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_cover_count_one_to_one_needs_one() {
        let pattern = DistributionPattern::OneToOne;
        assert!(validate_cover_count(&pattern, 1).is_ok());
        assert!(validate_cover_count(&pattern, 0).is_err());
    }

    #[test]
    fn validate_cover_count_one_to_many() {
        let pattern = DistributionPattern::OneToMany {
            data_shards: 5,
            parity_shards: 3,
        };
        assert!(validate_cover_count(&pattern, 8).is_ok());
        assert!(validate_cover_count(&pattern, 7).is_err());
    }

    #[test]
    fn validate_cover_count_many_to_one() {
        let pattern = DistributionPattern::ManyToOne;
        assert!(validate_cover_count(&pattern, 1).is_ok());
    }

    #[test]
    fn validate_cover_count_many_to_many() {
        let pattern = DistributionPattern::ManyToMany {
            mode: ManyToManyMode::Replicate,
        };
        assert!(validate_cover_count(&pattern, 2).is_ok());
        assert!(validate_cover_count(&pattern, 1).is_err());
    }

    #[test]
    fn assign_one_to_many_round_robin() {
        let assignments = assign_one_to_many(6, 3);
        assert_eq!(
            assignments,
            vec![(0, 0), (1, 1), (2, 2), (3, 0), (4, 1), (5, 2)]
        );
    }

    #[test]
    fn assign_many_to_many_replicate() {
        let assignments = assign_many_to_many(ManyToManyMode::Replicate, 2, 3, 0);
        assert_eq!(assignments, vec![vec![0, 1, 2], vec![0, 1, 2]]);
    }

    #[test]
    fn assign_many_to_many_stripe() {
        let assignments = assign_many_to_many(ManyToManyMode::Stripe, 4, 3, 0);
        assert_eq!(assignments, vec![vec![0], vec![1], vec![2], vec![0]]);
    }

    #[test]
    fn assign_many_to_many_diagonal() {
        let assignments = assign_many_to_many(ManyToManyMode::Diagonal, 3, 3, 0);
        // shard 0 → covers [0, 1], shard 1 → covers [1, 2], shard 2 → covers [2, 0]
        assert_eq!(assignments, vec![vec![0, 1], vec![1, 2], vec![2, 0]]);
    }

    #[test]
    fn assign_many_to_many_random_deterministic() {
        let a1 = assign_many_to_many(ManyToManyMode::Random, 5, 3, 42);
        let a2 = assign_many_to_many(ManyToManyMode::Random, 5, 3, 42);
        assert_eq!(a1, a2);
    }

    #[test]
    fn pack_unpack_round_trip() {
        let payloads = vec![
            Payload::from_bytes(b"hello".to_vec()),
            Payload::from_bytes(b"world".to_vec()),
            Payload::from_bytes(b"!".to_vec()),
        ];
        let packed = pack_many_payloads(&payloads);
        let unpacked = unpack_many_payloads(&packed).expect("unpack should succeed");
        assert_eq!(unpacked.len(), 3);
        assert_eq!(unpacked[0].as_bytes(), b"hello");
        assert_eq!(unpacked[1].as_bytes(), b"world");
        assert_eq!(unpacked[2].as_bytes(), b"!");
    }

    #[test]
    fn unpack_empty_buffer_errors() {
        assert!(unpack_many_payloads(&[]).is_err());
    }

    #[test]
    fn unpack_truncated_buffer_errors() {
        let payloads = vec![Payload::from_bytes(b"test".to_vec())];
        let mut packed = pack_many_payloads(&payloads);
        packed.truncate(packed.len().strict_sub(2)); // corrupt
        assert!(unpack_many_payloads(&packed).is_err());
    }

    #[test]
    fn minimum_covers_values() {
        assert_eq!(minimum_covers(&DistributionPattern::OneToOne), 1);
        assert_eq!(minimum_covers(&DistributionPattern::ManyToOne), 1);
        assert_eq!(
            minimum_covers(&DistributionPattern::OneToMany {
                data_shards: 10,
                parity_shards: 5,
            }),
            15
        );
        assert_eq!(
            minimum_covers(&DistributionPattern::ManyToMany {
                mode: ManyToManyMode::Stripe,
            }),
            2
        );
    }
}
