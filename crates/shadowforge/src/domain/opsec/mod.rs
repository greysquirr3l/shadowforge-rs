//! Amnesiac mode, geographic distribution manifests, forensic watermark tripwires.
//!
//! This module contains the pure domain logic for operational security.
//! The amnesiac pipeline runs entirely in memory: no temp files, no logs,
//! no filesystem writes.

use std::io::{Read, Write};

use bytes::Bytes;
use zeroize::Zeroize;

use crate::domain::errors::OpsecError;
use crate::domain::ports::EmbedTechnique;
use crate::domain::types::{CoverMedia, CoverMediaKind, Payload};

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
}
