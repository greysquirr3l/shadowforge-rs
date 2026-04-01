//! Dead drop adapter implementing the [`DeadDropEncoder`] port.

use crate::domain::errors::DeadDropError;
use crate::domain::ports::{DeadDropEncoder, EmbedTechnique};
use crate::domain::types::{CoverMedia, Payload, PlatformProfile};

/// Adapter implementing platform-aware dead-drop encoding.
///
/// Delegates embedding to the provided [`EmbedTechnique`] and applies
/// platform-specific constraints (e.g. Telegram passes PNG losslessly,
/// while Instagram recompresses JPEGs).
pub struct DeadDropEncoderImpl;

impl DeadDropEncoderImpl {
    /// Create a new dead-drop encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DeadDropEncoderImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadDropEncoder for DeadDropEncoderImpl {
    fn encode_for_platform(
        &self,
        cover: CoverMedia,
        payload: &Payload,
        platform: &PlatformProfile,
        technique: &dyn EmbedTechnique,
    ) -> Result<CoverMedia, DeadDropError> {
        // Validate that the technique can handle this cover
        let capacity = technique
            .capacity(&cover)
            .map_err(|e| DeadDropError::EncodeFailed {
                reason: format!("capacity check failed: {e}"),
            })?;

        if capacity.bytes < payload.as_bytes().len() as u64 {
            return Err(DeadDropError::EncodeFailed {
                reason: format!(
                    "payload ({} bytes) exceeds cover capacity ({} bytes) for platform {platform:?}",
                    payload.as_bytes().len(),
                    capacity.bytes,
                ),
            });
        }

        // Embed the payload using the provided technique.
        // For lossless platforms (Telegram), a simple LSB embed suffices.
        // For lossy platforms (Instagram, Twitter, etc.), the caller should
        // provide a compression-survivable embedder (T18) — this adapter
        // delegates the strategy choice to the caller.
        let stego_cover = technique
            .embed(cover, payload)
            .map_err(|e| DeadDropError::EncodeFailed {
                reason: format!("embedding failed for platform {platform:?}: {e}"),
            })?;

        Ok(stego_cover)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::errors::StegoError;
    use crate::domain::types::{Capacity, CoverMediaKind, StegoTechnique};
    use bytes::Bytes;
    use std::collections::HashMap;

    struct MockEmbedder {
        cap: u64,
        fail_embed: bool,
    }

    impl EmbedTechnique for MockEmbedder {
        fn technique(&self) -> StegoTechnique {
            StegoTechnique::LsbImage
        }

        fn capacity(&self, _cover: &CoverMedia) -> Result<Capacity, StegoError> {
            Ok(Capacity {
                bytes: self.cap,
                technique: StegoTechnique::LsbImage,
            })
        }

        fn embed(
            &self,
            mut cover: CoverMedia,
            payload: &Payload,
        ) -> Result<CoverMedia, StegoError> {
            if self.fail_embed {
                return Err(StegoError::MalformedCoverData {
                    reason: "mock failure".into(),
                });
            }
            let mut data = cover.data.to_vec();
            data.extend_from_slice(payload.as_bytes());
            cover.data = Bytes::from(data);
            Ok(cover)
        }
    }

    fn make_cover() -> CoverMedia {
        CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(vec![0u8; 512]),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn encode_for_telegram_succeeds() {
        let encoder = DeadDropEncoderImpl::new();
        let cover = make_cover();
        let payload = Payload::from_bytes(vec![1, 2, 3, 4]);
        let mock = MockEmbedder {
            cap: 1024,
            fail_embed: false,
        };

        let result = encoder.encode_for_platform(
            cover,
            &payload,
            &PlatformProfile::Telegram,
            &mock,
        );

        assert!(result.is_ok());
        let stego = result.expect("should succeed");
        // Stego cover should be larger (payload appended by mock)
        assert!(stego.data.len() > 512);
    }

    #[test]
    fn encode_for_instagram_succeeds() {
        let encoder = DeadDropEncoderImpl::new();
        let cover = make_cover();
        let payload = Payload::from_bytes(vec![5, 6, 7]);
        let mock = MockEmbedder {
            cap: 1024,
            fail_embed: false,
        };

        let result = encoder.encode_for_platform(
            cover,
            &payload,
            &PlatformProfile::Instagram,
            &mock,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn encode_fails_when_payload_exceeds_capacity() {
        let encoder = DeadDropEncoderImpl::new();
        let cover = make_cover();
        let payload = Payload::from_bytes(vec![0u8; 100]);
        let mock = MockEmbedder {
            cap: 10, // Too small
            fail_embed: false,
        };

        let result = encoder.encode_for_platform(
            cover,
            &payload,
            &PlatformProfile::Twitter,
            &mock,
        );

        assert!(matches!(result, Err(DeadDropError::EncodeFailed { .. })));
    }

    #[test]
    fn encode_fails_when_embedder_fails() {
        let encoder = DeadDropEncoderImpl::new();
        let cover = make_cover();
        let payload = Payload::from_bytes(vec![1, 2, 3]);
        let mock = MockEmbedder {
            cap: 1024,
            fail_embed: true,
        };

        let result = encoder.encode_for_platform(
            cover,
            &payload,
            &PlatformProfile::Imgur,
            &mock,
        );

        assert!(matches!(result, Err(DeadDropError::EncodeFailed { .. })));
    }

    #[test]
    fn encode_works_with_custom_platform() {
        let encoder = DeadDropEncoderImpl::new();
        let cover = make_cover();
        let payload = Payload::from_bytes(vec![10, 20, 30]);
        let mock = MockEmbedder {
            cap: 1024,
            fail_embed: false,
        };
        let platform = PlatformProfile::Custom {
            quality: 75,
            subsampling: crate::domain::types::ChromaSubsampling::Yuv422,
        };

        let result = encoder.encode_for_platform(cover, &payload, &platform, &mock);
        assert!(result.is_ok());
    }
}
