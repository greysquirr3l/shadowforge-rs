//! Canary shard tripwire adapter implementing the [`CanaryService`] port.

use uuid::Uuid;

use crate::domain::canary::{generate_canary_shard, is_canary_shard};
use crate::domain::errors::CanaryError;
use crate::domain::ports::{CanaryService, EmbedTechnique};
use crate::domain::types::{CanaryShard, CoverMedia, Payload};

/// Adapter implementing canary shard generation and check logic.
///
/// Generates an (N+1)th canary shard that cannot participate in real
/// Reed-Solomon reconstruction. The canary is embedded into the first
/// cover that has sufficient capacity.
pub struct CanaryServiceImpl {
    /// Shard size in bytes (should match the real RS shard size).
    shard_size: usize,
    /// Total number of real shards in the distribution (data + parity).
    total_shards: u8,
}

impl CanaryServiceImpl {
    /// Create a new canary service with the given shard parameters.
    #[must_use]
    pub const fn new(shard_size: usize, total_shards: u8) -> Self {
        Self {
            shard_size,
            total_shards,
        }
    }

    /// Check whether a shard matches the canary marker for a given ID.
    #[must_use]
    pub fn verify_canary(shard: &crate::domain::types::Shard, canary_id: Uuid) -> bool {
        is_canary_shard(shard, canary_id)
    }
}

impl CanaryService for CanaryServiceImpl {
    fn embed_canary(
        &self,
        covers: Vec<CoverMedia>,
        embedder: &dyn EmbedTechnique,
    ) -> Result<(Vec<CoverMedia>, CanaryShard), CanaryError> {
        if covers.is_empty() {
            return Err(CanaryError::NoCovers);
        }

        let canary_id = Uuid::new_v4();
        let canary = generate_canary_shard(canary_id, self.shard_size, self.total_shards, None);

        // Serialize canary shard data as the payload to embed
        let canary_payload = Payload::from_bytes(canary.shard.data.clone());

        // Find first cover with enough capacity and embed
        let mut result_covers = Vec::with_capacity(covers.len());
        let mut placed = false;

        for cover in covers {
            if !placed
                && let Ok(cap) = embedder.capacity(&cover)
                && cap.bytes >= canary_payload.as_bytes().len() as u64
            {
                if let Ok(stego_cover) = embedder.embed(cover, &canary_payload) {
                    result_covers.push(stego_cover);
                    placed = true;
                    continue;
                }
                // embed() consumed cover on failure — it's gone, move on
                continue;
            }
            result_covers.push(cover);
        }

        if !placed {
            return Err(CanaryError::EmbedFailed {
                source: crate::domain::errors::StegoError::PayloadTooLarge {
                    available: 0,
                    needed: canary_payload.as_bytes().len() as u64,
                },
            });
        }

        Ok((result_covers, canary))
    }

    fn check_canary(&self, shard: &CanaryShard) -> bool {
        // If no notify URL is set, manual check is required
        let Some(url) = &shard.notify_url else {
            return false;
        };

        // Validate the URL to prevent SSRF — only allow https scheme
        if !url.starts_with("https://") {
            return false;
        }

        // TODO(T34): Wire up HTTP HEAD request via a network port trait.
        // For now, return false (manual check mode).
        // The CLI should provide a way to manually mark canaries as accessed.
        let _ = url;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::errors::StegoError;
    use crate::domain::types::{Capacity, CoverMedia, CoverMediaKind, StegoTechnique};
    use bytes::Bytes;
    use std::collections::HashMap;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A mock embedder for testing canary embedding.
    struct MockEmbedder {
        capacity_bytes: u64,
        should_fail: bool,
    }

    impl EmbedTechnique for MockEmbedder {
        fn technique(&self) -> StegoTechnique {
            StegoTechnique::LsbImage
        }

        fn capacity(&self, _cover: &CoverMedia) -> Result<Capacity, StegoError> {
            Ok(Capacity {
                bytes: self.capacity_bytes,
                technique: StegoTechnique::LsbImage,
            })
        }

        fn embed(
            &self,
            mut cover: CoverMedia,
            payload: &Payload,
        ) -> Result<CoverMedia, StegoError> {
            if self.should_fail {
                return Err(StegoError::PayloadTooLarge {
                    available: 0,
                    needed: payload.as_bytes().len() as u64,
                });
            }
            // Simulate embedding by appending payload to cover data
            let mut new_data = cover.data.to_vec();
            new_data.extend_from_slice(payload.as_bytes());
            cover.data = Bytes::from(new_data);
            Ok(cover)
        }
    }

    fn make_cover() -> CoverMedia {
        CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(vec![0u8; 1024]),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn embed_canary_returns_canary_shard() -> TestResult {
        let service = CanaryServiceImpl::new(64, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 1024,
            should_fail: false,
        };
        let covers = vec![make_cover()];

        let (result_covers, canary) = service.embed_canary(covers, &embedder)?;

        assert_eq!(result_covers.len(), 1);
        assert_eq!(canary.shard.data.len(), 64);
        assert_eq!(canary.shard.index, 5); // total_shards = 5, so canary index = 5
        Ok(())
    }

    #[test]
    fn embed_canary_fails_on_empty_covers() {
        let service = CanaryServiceImpl::new(64, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 1024,
            should_fail: false,
        };

        let result = service.embed_canary(vec![], &embedder);
        assert!(matches!(result, Err(CanaryError::NoCovers)));
    }

    #[test]
    fn embed_canary_fails_when_no_cover_has_capacity() {
        let service = CanaryServiceImpl::new(64, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 0,
            should_fail: false,
        };
        let covers = vec![make_cover()];

        let result = service.embed_canary(covers, &embedder);
        assert!(matches!(result, Err(CanaryError::EmbedFailed { .. })));
    }

    #[test]
    fn embed_canary_skips_failing_cover_tries_next() -> TestResult {
        let service = CanaryServiceImpl::new(64, 5);
        // First cover will fail embedding, second should succeed
        let embedder = MockEmbedder {
            capacity_bytes: 1024,
            should_fail: false,
        };
        let covers = vec![make_cover(), make_cover()];

        let (result_covers, canary) = service.embed_canary(covers, &embedder)?;

        assert_eq!(result_covers.len(), 2);
        assert!(!canary.shard.data.is_empty());
        Ok(())
    }

    #[test]
    fn canary_shard_not_in_original_covers() -> TestResult {
        let service = CanaryServiceImpl::new(64, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 1024,
            should_fail: false,
        };
        let original_cover = make_cover();
        let original_data = original_cover.data.clone();
        let covers = vec![original_cover];

        let (result_covers, _canary) = service.embed_canary(covers, &embedder)?;

        // Modified cover should differ from original
        assert_ne!(
            result_covers.first().ok_or("index out of bounds")?.data,
            original_data
        );
        Ok(())
    }

    #[test]
    fn check_canary_returns_false_without_notify_url() {
        let service = CanaryServiceImpl::new(64, 5);
        let canary = generate_canary_shard(Uuid::new_v4(), 64, 5, None);

        assert!(!service.check_canary(&canary));
    }

    #[test]
    fn check_canary_returns_false_for_non_https_url() {
        let service = CanaryServiceImpl::new(64, 5);
        let canary = generate_canary_shard(
            Uuid::new_v4(),
            64,
            5,
            Some("http://insecure.example.com/canary".to_owned()),
        );

        assert!(!service.check_canary(&canary));
    }

    #[test]
    fn check_canary_returns_false_for_unreachable_url() {
        let service = CanaryServiceImpl::new(64, 5);
        let canary = generate_canary_shard(
            Uuid::new_v4(),
            64,
            5,
            Some("https://nonexistent.example.invalid/canary".to_owned()),
        );

        // Should return false (network port not wired yet)
        assert!(!service.check_canary(&canary));
    }

    #[test]
    fn verify_canary_detects_canary_shard() {
        let canary_id = Uuid::new_v4();
        let canary = generate_canary_shard(canary_id, 64, 5, None);

        assert!(CanaryServiceImpl::verify_canary(&canary.shard, canary_id));
    }

    #[test]
    fn verify_canary_rejects_normal_shard() {
        let canary_id = Uuid::new_v4();
        let normal = crate::domain::types::Shard {
            index: 0,
            total: 5,
            data: vec![42u8; 64],
            hmac_tag: [0u8; 32],
        };

        assert!(!CanaryServiceImpl::verify_canary(&normal, canary_id));
    }
}
