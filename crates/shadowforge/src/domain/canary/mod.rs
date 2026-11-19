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

/// The marker that identifies a canary.
///
/// The marker is a SHA-256 of the `canary_id`, repeated to fill the shard.
/// A shard shorter than the digest holds a prefix of it, so the marker is
/// compared only over the bytes that are actually present.
fn canary_marker(canary_id: Uuid) -> [u8; 32] {
    Sha256::digest(canary_id.as_bytes()).into()
}

/// The fewest marker bytes that count as an identification.
///
/// A payload shorter than this is not reported as the canary. The
/// comparison is over the bytes the payload actually holds, so a one-byte
/// payload would match the marker's first byte with probability 1/256 —
/// a false alarm on the very signal that is supposed to be worth acting
/// on. Eight bytes puts the chance of a false match at 2⁻⁶⁴.
const MIN_MARKER_BYTES: usize = 8;

/// Compare `data` against the canary marker for `canary_id`.
///
/// The comparison is constant-time over the bytes that `data` actually
/// holds, so a canary embedded in a shard shorter than the digest is still
/// recognised. A payload shorter than the marker is compared over its own
/// length — that is the truncated prefix of the marker, which is what
/// `generate_canary_shard` wrote.
///
/// Returns `false` for a payload too short to identify anything: an empty
/// payload carries no marker at all, and a very short one would match by
/// chance rather than by being the canary.
fn matches_canary_marker(data: &[u8], canary_id: Uuid) -> bool {
    use subtle::ConstantTimeEq;

    let marker = canary_marker(canary_id);
    let len = data.len().min(marker.len());
    if len < MIN_MARKER_BYTES {
        return false;
    }
    let Some(candidate) = data.get(..len) else {
        return false;
    };
    let Some(expected) = marker.get(..len) else {
        return false;
    };
    candidate.ct_eq(expected).into()
}

/// Check whether a given shard is the canary by verifying its data matches
/// the SHA-256 marker derived from the `canary_id`.
///
/// This is a constant-time comparison to avoid timing side channels.
#[must_use]
pub fn is_canary_shard(shard: &Shard, canary_id: Uuid) -> bool {
    matches_canary_marker(&shard.data, canary_id)
}

/// Check whether a recovered payload is the canary.
///
/// This is the check that matters operationally. A party who does not know
/// what the canary is holds nothing but the bytes recovered from a cover,
/// so the payload — not the shard — is what gets tested.
///
/// The comparison is constant-time, and the payload only has to carry the
/// identifying prefix of the marker.
#[must_use]
pub fn is_canary_payload(payload: &[u8], canary_id: Uuid) -> bool {
    matches_canary_marker(payload, canary_id)
}

/// The fewest marker bytes a canary must carry to be identifiable.
///
/// A canary in a shard shorter than this cannot be told apart from an
/// arbitrary payload, so the adapter refuses to plant one rather than
/// making a tripwire that never fires.
#[must_use]
pub const fn min_canary_bytes() -> usize {
    MIN_MARKER_BYTES
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

    #[test]
    fn a_shard_shorter_than_the_digest_is_still_detected() {
        // A shard smaller than the 32-byte digest holds a truncated
        // marker. Detection has to work over the bytes that are actually
        // present, or a short canary is never recognised.
        let canary_id = Uuid::new_v4();
        for shard_size in [8usize, 12, 16, 31, 32] {
            let canary = generate_canary_shard(canary_id, shard_size, 5, None);
            assert_eq!(canary.shard.data.len(), shard_size);
            assert!(
                is_canary_shard(&canary.shard, canary_id),
                "a {shard_size}-byte canary shard should be detected"
            );
            assert!(
                is_canary_payload(&canary.shard.data, canary_id),
                "a {shard_size}-byte canary payload should be detected"
            );
        }
    }

    #[test]
    fn a_short_canary_is_detected_from_the_raw_payload() {
        // The operational path: a party recovers the bytes from a cover
        // and those bytes are tested directly.
        let canary_id = Uuid::new_v4();
        let canary = generate_canary_shard(canary_id, 12, 5, None);

        assert!(is_canary_payload(&canary.shard.data, canary_id));
    }

    #[test]
    fn a_truncated_canary_prefix_is_detected() {
        // A party who extracted only part of the payload still holds the
        // identifying prefix.
        let canary_id = Uuid::new_v4();
        let canary = generate_canary_shard(canary_id, 64, 5, None);

        let prefix8 = canary.shard.data.get(..8);
        let prefix32 = canary.shard.data.get(..32);
        assert!(is_canary_payload(prefix8.unwrap_or_default(), canary_id));
        assert!(is_canary_payload(prefix32.unwrap_or_default(), canary_id));
    }

    #[test]
    fn an_empty_payload_is_not_the_canary() {
        // An empty payload carries no marker, so it must not be reported
        // as the canary.
        let canary_id = Uuid::new_v4();

        assert!(!is_canary_payload(&[], canary_id));
    }

    #[test]
    fn a_payload_too_short_to_identify_is_not_the_canary() {
        // A one-byte payload would match the marker's first byte with
        // probability 1/256, so it is not treated as an identification.
        let canary_id = Uuid::new_v4();
        let canary = generate_canary_shard(canary_id, 64, 5, None);

        let short = canary.shard.data.get(..3);
        assert!(!is_canary_payload(short.unwrap_or_default(), canary_id));
    }

    #[test]
    fn the_marker_prefix_of_a_real_canary_is_identified() {
        // The cut-off is at eight bytes, so the canary's own prefix is
        // still recognised at exactly that length.
        let canary_id = Uuid::new_v4();
        let canary = generate_canary_shard(canary_id, 64, 5, None);

        let prefix = canary.shard.data.get(..min_canary_bytes());
        assert!(is_canary_payload(prefix.unwrap_or_default(), canary_id));
    }

    #[test]
    fn a_short_payload_that_is_not_the_marker_is_not_the_canary() {
        let canary_id = Uuid::new_v4();

        assert!(!is_canary_payload(&[0u8; 4], canary_id));
        assert!(!is_canary_payload(&[0u8; 12], canary_id));
    }
}
