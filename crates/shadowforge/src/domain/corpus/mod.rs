//! Corpus steganography: zero-modification cover selection via ANN search.
//!
//! Given a payload to embed and a corpus of images, this module finds
//! the image whose natural LSB bit pattern most closely matches the
//! payload — minimising or eliminating modifications needed.

use bytes::Bytes;

use crate::domain::types::CorpusEntry;

/// Compute the Hamming distance between two byte slices of equal length.
///
/// Returns `None` if the slices differ in length.
#[must_use]
pub fn hamming_distance(a: &[u8], b: &[u8]) -> Option<u64> {
    if a.len() != b.len() {
        return None;
    }
    let mut dist: u64 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        dist = dist.strict_add(u64::from((x ^ y).count_ones()));
    }
    Some(dist)
}

/// Extract the LSB bit pattern from raw pixel bytes.
///
/// For each byte of pixel data, extracts the least significant bit and packs
/// 8 bits into one output byte. The result length is `ceil(pixel_bytes.len() / 8)`.
#[must_use]
pub fn extract_lsb_pattern(pixel_bytes: &[u8]) -> Bytes {
    let out_len = pixel_bytes.len().div_ceil(8);
    let mut pattern = vec![0u8; out_len];

    for (i, &byte) in pixel_bytes.iter().enumerate() {
        let out_byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        if byte & 1 == 1 {
            // out_byte_idx = i/8 <= (pixel_bytes.len()-1)/8 < out_len
            #[expect(
                clippy::indexing_slicing,
                reason = "out_byte_idx = i/8 < ceil(len/8) = out_len"
            )]
            {
                pattern[out_byte_idx] |= 1 << bit_idx;
            }
        }
    }

    Bytes::from(pattern)
}

/// Expand a payload into a bit pattern of the same format as
/// [`extract_lsb_pattern`] output (one bit per sample, packed into bytes).
///
/// This effectively returns the raw bytes padded to a target bit-count
/// boundary. If `target_bits` is `None`, returns the payload bytes as-is.
#[must_use]
pub fn payload_to_bit_pattern(payload: &[u8], target_bits: Option<usize>) -> Bytes {
    target_bits.map_or_else(
        || Bytes::copy_from_slice(payload),
        |target| {
            let needed_bytes = target.div_ceil(8);
            let mut result = Vec::with_capacity(needed_bytes);
            result.extend_from_slice(payload);
            result.resize(needed_bytes, 0);
            Bytes::from(result)
        },
    )
}

/// Score a corpus entry's precomputed bit pattern against a payload pattern.
///
/// Returns the Hamming distance — lower is better. Returns `u64::MAX` if the
/// patterns are incompatible in length.
#[must_use]
pub fn score_match(corpus_pattern: &[u8], payload_pattern: &[u8]) -> u64 {
    // Compare only the overlapping prefix
    let compare_len = corpus_pattern.len().min(payload_pattern.len());
    if compare_len == 0 {
        return u64::MAX;
    }
    match (
        corpus_pattern.get(..compare_len),
        payload_pattern.get(..compare_len),
    ) {
        (Some(a), Some(b)) => hamming_distance(a, b).unwrap_or(u64::MAX),
        _ => u64::MAX,
    }
}

/// Determine if a Hamming distance counts as a "close enough" match.
///
/// Threshold: fewer than 5% of total bits differ.
#[must_use]
pub const fn is_close_match(distance: u64, total_bits: u64) -> bool {
    if total_bits == 0 {
        return false;
    }
    // ≤ 5% of bits differ
    distance.strict_mul(20) <= total_bits
}

/// Filter corpus entries by model ID and resolution.
///
/// Returns references to all entries whose `spectral_key` matches both
/// `model_id` and `resolution`. Entries without a `spectral_key` are
/// silently excluded.
#[must_use]
pub fn filter_by_model<'a>(
    entries: &'a [CorpusEntry],
    model_id: &str,
    resolution: (u32, u32),
) -> Vec<&'a CorpusEntry> {
    entries
        .iter()
        .filter(|e| {
            e.spectral_key
                .as_ref()
                .is_some_and(|k| k.model_id == model_id && k.resolution == resolution)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_identical() {
        let a = [0xAA, 0x55, 0xFF];
        let b = [0xAA, 0x55, 0xFF];
        assert_eq!(hamming_distance(&a, &b), Some(0));
    }

    #[test]
    fn hamming_distance_one_bit() {
        let a = [0b0000_0000];
        let b = [0b0000_0001];
        assert_eq!(hamming_distance(&a, &b), Some(1));
    }

    #[test]
    fn hamming_distance_all_bits() {
        let a = [0x00];
        let b = [0xFF];
        assert_eq!(hamming_distance(&a, &b), Some(8));
    }

    #[test]
    fn hamming_distance_unequal_lengths() {
        let a = [0x00, 0x00];
        let b = [0xFF];
        assert_eq!(hamming_distance(&a, &b), None);
    }

    #[test]
    fn extract_lsb_pattern_basic() {
        // 8 bytes: LSBs = 1,0,1,0,1,0,1,0 = 0xAA
        let pixels = [0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00];
        let pattern = extract_lsb_pattern(&pixels);
        assert_eq!(pattern.as_ref(), &[0xAA]);
    }

    #[test]
    fn extract_lsb_pattern_partial_byte() {
        // 3 bytes: LSBs = 1,1,0 → packed into 0b1100_0000 = 0xC0
        let pixels = [0x01, 0x03, 0x00];
        let pattern = extract_lsb_pattern(&pixels);
        assert_eq!(pattern.len(), 1);
        assert_eq!(pattern.as_ref(), &[0b1100_0000]);
    }

    #[test]
    fn payload_to_bit_pattern_no_target() {
        let payload = b"hello";
        let result = payload_to_bit_pattern(payload, None);
        assert_eq!(result.as_ref(), b"hello");
    }

    #[test]
    fn payload_to_bit_pattern_with_padding() {
        let payload = b"\xFF";
        let result = payload_to_bit_pattern(payload, Some(16)); // 16 bits = 2 bytes
        assert_eq!(result.len(), 2);
        assert_eq!(result.as_ref(), &[0xFF, 0x00]);
    }

    #[test]
    fn score_match_identical() {
        let a = [0xAA, 0x55];
        let b = [0xAA, 0x55];
        assert_eq!(score_match(&a, &b), 0);
    }

    #[test]
    fn score_match_empty() {
        let a: [u8; 0] = [];
        let b: [u8; 0] = [];
        assert_eq!(score_match(&a, &b), u64::MAX);
    }

    #[test]
    fn is_close_match_zero_distance() {
        assert!(is_close_match(0, 100));
    }

    #[test]
    fn is_close_match_exactly_five_percent() {
        // 5 differing out of 100 total = exactly 5%
        assert!(is_close_match(5, 100));
    }

    #[test]
    fn is_close_match_above_threshold() {
        // 6 differing out of 100 total = 6% > 5%
        assert!(!is_close_match(6, 100));
    }

    #[test]
    fn is_close_match_zero_total() {
        assert!(!is_close_match(0, 0));
    }

    // ─── filter_by_model tests ────────────────────────────────────────────────

    fn make_entry(model_id: Option<&str>, resolution: Option<(u32, u32)>) -> CorpusEntry {
        use crate::domain::types::{CoverMediaKind, SpectralKey};
        CorpusEntry {
            file_hash: [0u8; 32],
            path: "test.png".to_string(),
            cover_kind: CoverMediaKind::PngImage,
            precomputed_bit_pattern: Bytes::new(),
            spectral_key: model_id.zip(resolution).map(|(id, res)| SpectralKey {
                model_id: id.to_string(),
                resolution: res,
            }),
        }
    }

    #[test]
    fn filter_by_model_returns_matching_entries() {
        let entries = vec![
            make_entry(Some("gemini"), Some((1024, 1024))),
            make_entry(Some("gemini"), Some((512, 512))),
            make_entry(Some("other"), Some((1024, 1024))),
            make_entry(None, None),
        ];
        let result = filter_by_model(&entries, "gemini", (1024, 1024));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_by_model_returns_empty_when_no_match() {
        let entries = vec![
            make_entry(Some("gemini"), Some((512, 512))),
            make_entry(None, None),
        ];
        let result = filter_by_model(&entries, "gemini", (1024, 1024));
        assert!(result.is_empty());
    }

    #[test]
    fn filter_by_model_excludes_no_key_entries() {
        let entries = vec![make_entry(None, None), make_entry(None, None)];
        let result = filter_by_model(&entries, "gemini", (1024, 1024));
        assert!(result.is_empty());
    }
}
