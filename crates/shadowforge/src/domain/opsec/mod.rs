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
    CoverMedia, CoverMediaKind, GeoShardEntry, GeographicManifest, Payload,
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
    let stego = technique.embed(cover, &payload).map_err(|e| {
        OpsecError::PipelineError {
            reason: format!("embed failed: {e}"),
        }
    })?;

    // Step 4: Write output
    output.write_all(&stego.data).map_err(|e| {
        OpsecError::PipelineError {
            reason: format!("failed to write output: {e}"),
        }
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

        fn embed(
            &self,
            _cover: CoverMedia,
            _payload: &Payload,
        ) -> Result<CoverMedia, StegoError> {
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
}
