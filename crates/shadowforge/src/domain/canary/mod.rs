//! Canary shard tripwires for distribution compromise detection.
//!
//! A canary shard is an extra shard planted in a honeypot location. It cannot
//! complete Reed-Solomon reconstruction on its own (not counted in K), but
//! access to it signals that the distribution has been compromised.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::types::{CanaryShard, Shard};

/// Generate a canary shard that looks plausible but cannot participate in
/// real Reed-Solomon reconstruction.
///
/// The shard's `data` field contains a SHA-256 hash of the `canary_id`,
/// allowing the distribution owner to identify it without revealing this
/// to partial shard holders. The HMAC tag is derived with the `canary_id`
/// mixed into the key so it will fail normal HMAC verification.
#[must_use]
pub fn generate_canary_shard(
    canary_id: Uuid,
    shard_size: usize,
    total_shards: u8,
    notify_url: Option<String>,
) -> CanaryShard {
    // Marker: SHA-256(canary_id) — repeated to fill shard_size
    let marker = Sha256::digest(canary_id.as_bytes());
    let mut data = Vec::with_capacity(shard_size);
    while data.len() < shard_size {
        let remaining = shard_size.saturating_sub(data.len());
        let chunk = remaining.min(marker.len());
        // SAFETY: chunk <= marker.len() by `.min()` above
        #[expect(clippy::indexing_slicing, reason = "chunk bounded by marker.len()")]
        data.extend_from_slice(&marker[..chunk]);
    }

    // Use total_shards as the index (one beyond the valid range 0..total_shards-1)
    // This makes the canary shard's index invalid for RS reconstruction.
    let canary_index = total_shards;

    // HMAC tag: derive from canary_id mixed into a pseudo-key so it won't
    // match any legitimate shard HMAC.
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(canary_id.as_bytes());
    hmac_input.push(canary_index);
    hmac_input.push(total_shards);
    hmac_input.extend_from_slice(&data);
    let hmac_tag: [u8; 32] = Sha256::digest(&hmac_input).into();

    let shard = Shard {
        index: canary_index,
        total: total_shards,
        data,
        hmac_tag,
    };

    CanaryShard {
        shard,
        canary_id,
        notify_url,
    }
}

/// Check whether a given shard is the canary by verifying its data matches
/// the SHA-256 marker derived from the `canary_id`.
///
/// This is a constant-time comparison to avoid timing side channels.
#[must_use]
pub fn is_canary_shard(shard: &Shard, canary_id: Uuid) -> bool {
    use subtle::ConstantTimeEq;

    let marker = Sha256::digest(canary_id.as_bytes());
    if shard.data.len() < marker.len() {
        return false;
    }
    // Compare the first 32 bytes of shard data against the marker
    shard
        .data
        .get(..marker.len())
        .is_some_and(|prefix| prefix.ct_eq(&marker).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_shard_has_correct_size() {
        let canary_id = Uuid::new_v4();
        let shard_size = 128;
        let total = 5;

        let canary = generate_canary_shard(canary_id, shard_size, total, None);

        assert_eq!(canary.shard.data.len(), shard_size);
        assert_eq!(canary.canary_id, canary_id);
        assert!(canary.notify_url.is_none());
    }

    #[test]
    fn canary_shard_index_is_beyond_valid_range() {
        let canary_id = Uuid::new_v4();
        let total = 5;

        let canary = generate_canary_shard(canary_id, 64, total, None);

        // Index should be total_shards (one beyond valid 0..total-1)
        assert_eq!(canary.shard.index, total);
    }

    #[test]
    fn canary_shard_data_contains_marker() {
        let canary_id = Uuid::new_v4();
        let canary = generate_canary_shard(canary_id, 64, 5, None);

        assert!(is_canary_shard(&canary.shard, canary_id));
    }

    #[test]
    fn canary_shard_not_detected_with_wrong_id() {
        let canary_id = Uuid::new_v4();
        let wrong_id = Uuid::new_v4();
        let canary = generate_canary_shard(canary_id, 64, 5, None);

        assert!(!is_canary_shard(&canary.shard, wrong_id));
    }

    #[test]
    fn canary_shard_preserves_notify_url() {
        let canary_id = Uuid::new_v4();
        let url = "https://example.com/canary/abc123".to_owned();

        let canary = generate_canary_shard(canary_id, 64, 5, Some(url.clone()));

        assert_eq!(canary.notify_url.as_deref(), Some(url.as_str()));
    }

    #[test]
    fn normal_shard_not_detected_as_canary() {
        let canary_id = Uuid::new_v4();
        let normal = Shard {
            index: 0,
            total: 5,
            data: vec![0u8; 64],
            hmac_tag: [0u8; 32],
        };

        assert!(!is_canary_shard(&normal, canary_id));
    }

    #[test]
    fn different_canary_ids_produce_different_shards() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let c1 = generate_canary_shard(id1, 64, 5, None);
        let c2 = generate_canary_shard(id2, 64, 5, None);

        assert_ne!(c1.shard.data, c2.shard.data);
        assert_ne!(c1.shard.hmac_tag, c2.shard.hmac_tag);
    }
}
