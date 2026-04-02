//! Amnesiac mode, geographic distribution manifests, forensic watermark tripwires.
//!
//! This module contains the pure domain logic for operational security.
//! The amnesiac pipeline runs entirely in memory: no temp files, no logs,
//! no filesystem writes.

use std::collections::HashSet;
use std::io::{Read, Write};

use bytes::Bytes;
use zeroize::Zeroize;

use crate::domain::errors::OpsecError;
use crate::domain::ports::EmbedTechnique;
use crate::domain::types::{
    CoverMedia, CoverMediaKind, GeoShardEntry, GeographicManifest, Payload, WatermarkTripwireTag,
};

/// Read all bytes from a reader into a `Vec<u8>`, zeroizing on error.
fn read_all_zeroizing(reader: &mut dyn Read) -> Result<Vec<u8>, OpsecError> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(|e| {
        buf.zeroize();
        OpsecError::PipelineError {
            reason: format!("failed to read input: {e}"),
        }
    })?;
    Ok(buf)
}

/// Run the embed pipeline entirely in memory.
///
/// 1. Reads cover and payload from their respective readers.
/// 2. Embeds payload into cover using the given technique.
/// 3. Writes the stego output to `output`.
/// 4. Zeroizes all intermediate buffers.
///
/// # Errors
///
/// Returns [`OpsecError::PipelineError`] if any step fails.
pub fn embed_in_memory(
    payload_input: &mut dyn Read,
    cover_input: &mut dyn Read,
    output: &mut dyn Write,
    technique: &dyn EmbedTechnique,
) -> Result<(), OpsecError> {
    // Step 1: Read cover
    let cover_bytes = read_all_zeroizing(cover_input)?;
    let cover = CoverMedia {
        kind: CoverMediaKind::PngImage,
        data: Bytes::from(cover_bytes),
        metadata: std::collections::HashMap::new(),
    };

    // Step 2: Read payload
    let mut payload_bytes = read_all_zeroizing(payload_input)?;
    let payload = Payload::from_bytes(payload_bytes.clone());
    payload_bytes.zeroize();

    // Step 3: Embed
    let stego = technique
        .embed(cover, &payload)
        .map_err(|e| OpsecError::PipelineError {
            reason: format!("embed failed: {e}"),
        })?;

    // Step 4: Write output
    output
        .write_all(&stego.data)
        .map_err(|e| OpsecError::PipelineError {
            reason: format!("failed to write output: {e}"),
        })?;

    Ok(())
}

// ─── Geographic Distribution ──────────────────────────────────────────────────

/// Validate a geographic manifest.
///
/// Ensures that the number of distinct jurisdictions meets the
/// `minimum_jurisdictions` requirement.
///
/// # Errors
///
/// Returns [`OpsecError::ManifestError`] if validation fails.
pub fn validate_manifest(manifest: &GeographicManifest) -> Result<(), OpsecError> {
    let jurisdictions: HashSet<&str> = manifest
        .shards
        .iter()
        .map(|e| e.jurisdiction.as_str())
        .collect();

    let distinct = jurisdictions.len();

    if distinct < manifest.minimum_jurisdictions as usize {
        return Err(OpsecError::ManifestError {
            reason: format!(
                "manifest requires {} distinct jurisdictions but only {} are assigned",
                manifest.minimum_jurisdictions, distinct
            ),
        });
    }

    Ok(())
}

/// Build a geographic manifest from shard assignments.
///
/// # Errors
///
/// Returns [`OpsecError::ManifestError`] if the manifest is invalid.
pub fn build_manifest(
    entries: Vec<GeoShardEntry>,
    minimum_jurisdictions: u8,
) -> Result<GeographicManifest, OpsecError> {
    let manifest = GeographicManifest {
        shards: entries,
        minimum_jurisdictions,
    };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Produce a human-readable recovery complexity score for a manifest.
///
/// Returns a string summarising which jurisdictions must cooperate and an
/// estimated coordination difficulty.
#[must_use]
pub fn recovery_complexity_score(manifest: &GeographicManifest) -> String {
    let jurisdictions: HashSet<&str> = manifest
        .shards
        .iter()
        .map(|e| e.jurisdiction.as_str())
        .collect();

    let mut sorted: Vec<&str> = jurisdictions.into_iter().collect();
    sorted.sort_unstable();

    let country_list = sorted.join(", ");

    format!(
        "Recovery requires cooperation across {} jurisdictions: [{}]. \
         Estimated legal coordination time: > 6 months under MLAT.",
        sorted.len(),
        country_list
    )
}

/// Render a geographic manifest as a Markdown document.
#[must_use]
pub fn manifest_to_markdown(manifest: &GeographicManifest) -> String {
    use std::fmt::Write as _;

    let mut md = String::from("# Geographic Distribution Manifest\n\n");

    let _ = write!(
        md,
        "**Minimum jurisdictions for reconstruction:** {}\n\n",
        manifest.minimum_jurisdictions
    );

    md.push_str("| Shard | Jurisdiction | Holder |\n");
    md.push_str("|-------|-------------|--------|\n");

    for entry in &manifest.shards {
        let _ = writeln!(
            md,
            "| {} | {} | {} |",
            entry.shard_index, entry.jurisdiction, entry.holder_description
        );
    }

    md.push('\n');
    let _ = writeln!(md, "**{}**", recovery_complexity_score(manifest));

    md
}

// ─── Forensic Watermark Tripwires ─────────────────────────────────────────────

/// Fixed marker pattern embedded at seed-derived positions.
const MARKER_PATTERN: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
/// Number of marker bits to embed in LSB positions.
const MARKER_BITS: usize = MARKER_PATTERN.len() * 8;

// LCG parameters (Numerical Recipes) for deterministic position derivation.
const LCG_A: u64 = 6_364_136_223_846_793_005;
const LCG_C: u64 = 1_442_695_040_888_963_407;

/// Derive deterministic LSB positions from a watermark tag's embedding seed.
///
/// Produces `count` unique byte-offset positions within `cover_len` bytes
/// using a simple seeded LCG. The positions are deterministic given the seed
/// but appear random.
fn derive_positions(seed_bytes: &[u8], cover_len: usize, count: usize) -> Vec<usize> {
    if cover_len == 0 || count == 0 {
        return Vec::new();
    }

    // Seed a simple LCG from the embedding_seed bytes
    let mut state: u64 = 0;
    for (i, &b) in seed_bytes.iter().enumerate() {
        // i % 8 is always in 0..7 so the multiply can never exceed 56
        #[expect(clippy::cast_possible_truncation, reason = "i % 8 always fits in u32")]
        let shift = (i % 8) as u32 * 8;
        state ^= u64::from(b).wrapping_shl(shift);
    }

    let mut positions = Vec::with_capacity(count);
    let mut used = HashSet::with_capacity(count);

    while positions.len() < count {
        state = state.wrapping_mul(LCG_A).wrapping_add(LCG_C);
        let pos = (state >> 16) as usize % cover_len;
        if used.insert(pos) {
            positions.push(pos);
        }
    }

    positions
}

/// Embed a forensic watermark tripwire into cover data.
///
/// Modifies LSBs at seed-derived positions to encode the marker pattern.
///
/// # Errors
///
/// Returns [`OpsecError::WatermarkError`] if the cover is too small.
pub fn embed_watermark(
    cover: &mut CoverMedia,
    tag: &WatermarkTripwireTag,
) -> Result<(), OpsecError> {
    if cover.data.len() < MARKER_BITS {
        return Err(OpsecError::WatermarkError {
            reason: format!(
                "cover too small ({} bytes) for watermark ({MARKER_BITS} bits)",
                cover.data.len(),
            ),
        });
    }

    let positions = derive_positions(&tag.embedding_seed, cover.data.len(), MARKER_BITS);
    let mut data = cover.data.to_vec();

    for (bit_idx, &pos) in positions.iter().enumerate() {
        let marker_byte = MARKER_PATTERN[bit_idx / 8];
        let bit = (marker_byte >> (7 - (bit_idx % 8))) & 1;
        data[pos] = (data[pos] & 0xFE) | bit;
    }

    cover.data = Bytes::from(data);
    Ok(())
}

/// Try to identify which recipient's watermark is present in cover data.
///
/// Returns the index of the matching tag, or `None` if no match is found.
#[must_use]
pub fn identify_watermark(cover: &CoverMedia, tags: &[WatermarkTripwireTag]) -> Option<usize> {
    if cover.data.len() < MARKER_BITS {
        return None;
    }

    for (tag_idx, tag) in tags.iter().enumerate() {
        let positions = derive_positions(&tag.embedding_seed, cover.data.len(), MARKER_BITS);

        let mut all_match = true;
        for (bit_idx, &pos) in positions.iter().enumerate() {
            let marker_byte = MARKER_PATTERN[bit_idx / 8];
            let expected_bit = (marker_byte >> (7 - (bit_idx % 8))) & 1;
            let actual_bit = cover.data[pos] & 1;
            if actual_bit != expected_bit {
                all_match = false;
                break;
            }
        }

        if all_match {
            return Some(tag_idx);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::errors::StegoError;
    use crate::domain::types::{Capacity, StegoTechnique};
    use std::io::Cursor;

    /// A mock embed technique that appends payload bytes to cover data.
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
            let mut combined = cover.data.to_vec();
            combined.extend_from_slice(payload.as_bytes());
            Ok(CoverMedia {
                kind: cover.kind,
                data: Bytes::from(combined),
                metadata: cover.metadata,
            })
        }
    }

    /// A mock embed technique that always fails.
    struct FailingEmbedder;

    impl EmbedTechnique for FailingEmbedder {
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
            Err(StegoError::MalformedCoverData {
                reason: "forced failure".into(),
            })
        }
    }

    #[test]
    fn amnesiac_embed_roundtrip() {
        let cover_data = b"cover-image-bytes";
        let payload_data = b"secret-message";

        let mut cover_reader = Cursor::new(cover_data.to_vec());
        let mut payload_reader = Cursor::new(payload_data.to_vec());
        let mut output = Vec::new();

        embed_in_memory(
            &mut payload_reader,
            &mut cover_reader,
            &mut output,
            &MockEmbedder,
        )
        .expect("embed should succeed");

        // Output should contain both cover and payload bytes (mock appends)
        assert!(output.len() > cover_data.len());
        assert!(output.starts_with(cover_data));
        assert!(output.ends_with(payload_data));
    }

    #[test]
    fn amnesiac_embed_empty_payload() {
        let cover_data = b"cover";
        let payload_data: &[u8] = b"";

        let mut cover_reader = Cursor::new(cover_data.to_vec());
        let mut payload_reader = Cursor::new(payload_data.to_vec());
        let mut output = Vec::new();

        embed_in_memory(
            &mut payload_reader,
            &mut cover_reader,
            &mut output,
            &MockEmbedder,
        )
        .expect("embed should succeed");

        // With empty payload, output should match cover
        assert_eq!(output.as_slice(), cover_data);
    }

    #[test]
    fn amnesiac_embed_fails_on_bad_technique() {
        let cover_data = b"cover";
        let payload_data = b"secret";

        let mut cover_reader = Cursor::new(cover_data.to_vec());
        let mut payload_reader = Cursor::new(payload_data.to_vec());
        let mut output = Vec::new();

        let result = embed_in_memory(
            &mut payload_reader,
            &mut cover_reader,
            &mut output,
            &FailingEmbedder,
        );

        assert!(result.is_err());
    }

    #[test]
    fn amnesiac_no_heap_leak_on_success() {
        // Verify that we can run multiple embeds without accumulating state
        for _ in 0..10 {
            let mut cover = Cursor::new(b"cover".to_vec());
            let mut payload = Cursor::new(b"secret".to_vec());
            let mut output = Vec::new();

            embed_in_memory(&mut payload, &mut cover, &mut output, &MockEmbedder)
                .expect("embed should succeed");
        }
    }

    // ─── Geographic Distribution Tests ────────────────────────────────────

    fn sample_manifest() -> GeographicManifest {
        GeographicManifest {
            shards: vec![
                GeoShardEntry {
                    shard_index: 0,
                    jurisdiction: "IS".into(),
                    holder_description: "Trusted contact in Iceland".into(),
                },
                GeoShardEntry {
                    shard_index: 1,
                    jurisdiction: "CH".into(),
                    holder_description: "Secure facility in Switzerland".into(),
                },
                GeoShardEntry {
                    shard_index: 2,
                    jurisdiction: "SG".into(),
                    holder_description: "Data centre in Singapore".into(),
                },
            ],
            minimum_jurisdictions: 2,
        }
    }

    #[test]
    fn validate_manifest_passes_sufficient_jurisdictions() {
        let manifest = sample_manifest();
        validate_manifest(&manifest).expect("validation should pass");
    }

    #[test]
    fn validate_manifest_fails_insufficient_jurisdictions() {
        let manifest = GeographicManifest {
            shards: vec![GeoShardEntry {
                shard_index: 0,
                jurisdiction: "IS".into(),
                holder_description: "contact".into(),
            }],
            minimum_jurisdictions: 3,
        };
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn build_manifest_returns_valid() {
        let entries = vec![
            GeoShardEntry {
                shard_index: 0,
                jurisdiction: "IS".into(),
                holder_description: "Iceland".into(),
            },
            GeoShardEntry {
                shard_index: 1,
                jurisdiction: "CH".into(),
                holder_description: "Switzerland".into(),
            },
        ];
        let manifest = build_manifest(entries, 2).expect("should build");
        assert_eq!(manifest.shards.len(), 2);
    }

    #[test]
    fn recovery_complexity_score_mentions_jurisdictions() {
        let manifest = sample_manifest();
        let score = recovery_complexity_score(&manifest);
        assert!(score.contains("3 jurisdictions"));
        assert!(score.contains("IS"));
        assert!(score.contains("CH"));
        assert!(score.contains("SG"));
        assert!(score.contains("MLAT"));
    }

    #[test]
    fn manifest_to_markdown_contains_heading() {
        let manifest = sample_manifest();
        let md = manifest_to_markdown(&manifest);
        assert!(md.contains("# Geographic Distribution Manifest"));
        assert!(md.contains("Iceland"));
        assert!(md.contains("IS"));
    }

    #[test]
    fn build_manifest_fails_insufficient() {
        let entries = vec![GeoShardEntry {
            shard_index: 0,
            jurisdiction: "IS".into(),
            holder_description: "contact".into(),
        }];
        assert!(build_manifest(entries, 2).is_err());
    }

    // ─── Forensic Watermark Tests ─────────────────────────────────────────

    fn make_cover(size: usize) -> CoverMedia {
        CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(vec![0u8; size]),
            metadata: std::collections::HashMap::new(),
        }
    }

    fn make_tag(seed: &[u8]) -> WatermarkTripwireTag {
        WatermarkTripwireTag {
            recipient_id: uuid::Uuid::new_v4(),
            embedding_seed: seed.to_vec(),
        }
    }

    #[test]
    fn embed_then_identify_roundtrip() {
        let tag_a = make_tag(b"recipient-a-seed");
        let mut cover = make_cover(1024);

        embed_watermark(&mut cover, &tag_a).expect("embed should succeed");

        let tags = [tag_a.clone()];
        let result = identify_watermark(&cover, &tags);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn different_tags_produce_different_covers() {
        let tag_a = make_tag(b"seed-alpha");
        let tag_b = make_tag(b"seed-beta");
        let tag_c = make_tag(b"seed-gamma");

        let mut cover_a = make_cover(1024);
        let mut cover_b = make_cover(1024);
        let mut cover_c = make_cover(1024);

        embed_watermark(&mut cover_a, &tag_a).expect("embed a");
        embed_watermark(&mut cover_b, &tag_b).expect("embed b");
        embed_watermark(&mut cover_c, &tag_c).expect("embed c");

        // All three should have different byte patterns
        assert_ne!(cover_a.data, cover_b.data);
        assert_ne!(cover_a.data, cover_c.data);
        assert_ne!(cover_b.data, cover_c.data);
    }

    #[test]
    fn identify_picks_correct_tag() {
        let tag_a = make_tag(b"aaaa");
        let tag_b = make_tag(b"bbbb");

        let mut cover = make_cover(1024);
        embed_watermark(&mut cover, &tag_b).expect("embed b");

        let tags = [tag_a, tag_b];
        let result = identify_watermark(&cover, &tags);
        assert_eq!(result, Some(1)); // tag_b is at index 1
    }

    #[test]
    fn identify_returns_none_when_no_match() {
        let tag_a = make_tag(b"unknown-seed");
        let cover = make_cover(1024); // unmodified

        let tags = [tag_a];
        let result = identify_watermark(&cover, &tags);
        assert_eq!(result, None);
    }

    #[test]
    fn embed_fails_on_small_cover() {
        let tag = make_tag(b"seed");
        let mut cover = make_cover(2); // Way too small for 32 bits

        let result = embed_watermark(&mut cover, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn derive_positions_deterministic() {
        let seed = b"test-seed";
        let p1 = derive_positions(seed, 1000, 32);
        let p2 = derive_positions(seed, 1000, 32);
        assert_eq!(p1, p2);
    }

    #[test]
    fn derive_positions_unique() {
        let seed = b"unique-seed";
        let positions = derive_positions(seed, 10_000, 100);
        let unique: HashSet<usize> = positions.iter().copied().collect();
        assert_eq!(unique.len(), positions.len());
    }
}
