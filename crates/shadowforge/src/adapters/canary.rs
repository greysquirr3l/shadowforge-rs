//! Canary shard tripwire adapter implementing the [`CanaryService`] port.

use uuid::Uuid;

use crate::domain::canary::{generate_canary_shard, is_canary_payload};
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
        crate::domain::canary::is_canary_shard(shard, canary_id)
    }
}

impl CanaryService for CanaryServiceImpl {
    fn embed_canary(
        &self,
        covers: Vec<CoverMedia>,
        canary_cover: CoverMedia,
        embedder: &dyn EmbedTechnique,
        notify_url: Option<String>,
    ) -> Result<(Vec<CoverMedia>, CoverMedia, CanaryShard), CanaryError> {
        if covers.is_empty() {
            return Err(CanaryError::NoCovers);
        }

        // A canary in a shard shorter than the marker cannot be told apart
        // from an arbitrary payload, so it would be a tripwire that never
        // fires. Better to say so than to plant one.
        if self.shard_size < crate::domain::canary::min_canary_bytes() {
            return Err(CanaryError::ShardTooSmall {
                shard_size: self.shard_size,
                minimum: crate::domain::canary::min_canary_bytes(),
            });
        }

        // A notification URL that cannot be reached would silently never
        // report, so it is rejected at setup rather than at tripwire time.
        if let Some(url) = &notify_url {
            validate_notify_url(url)?;
        }

        let canary_id = Uuid::new_v4();
        let canary =
            generate_canary_shard(canary_id, self.shard_size, self.total_shards, notify_url);

        // Serialize canary shard data as the payload to embed
        let canary_payload = Payload::from_bytes(canary.shard.data.clone());

        // The canary goes into its own cover. It is an (N+1)th shard, so
        // planting it on top of a real shard would destroy that shard and
        // quietly reduce the distribution's redundancy.
        let capacity = embedder
            .capacity(&canary_cover)
            .map_err(|source| CanaryError::EmbedFailed { source })?;
        if capacity.bytes < canary_payload.as_bytes().len() as u64 {
            return Err(CanaryError::EmbedFailed {
                source: crate::domain::errors::StegoError::PayloadTooLarge {
                    available: capacity.bytes,
                    needed: canary_payload.as_bytes().len() as u64,
                },
            });
        }

        let stego_canary_cover = embedder
            .embed(canary_cover, &canary_payload)
            .map_err(|source| CanaryError::EmbedFailed { source })?;

        Ok((covers, stego_canary_cover, canary))
    }

    fn check_canary(&self, payload: &[u8], canary_id: Uuid) -> bool {
        is_canary_payload(payload, canary_id)
    }
}

/// Reject a notification URL that is not HTTPS.
///
/// The canary notification says that a distribution was compromised. It
/// must not travel in clear text, and a URL that is not HTTPS could point
/// at a local file or an internal service.
fn validate_notify_url(url: &str) -> Result<(), CanaryError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(CanaryError::InvalidNotifyUrl {
            reason: "the URL is empty".into(),
        });
    }
    if !trimmed.starts_with("https://") {
        let scheme = trimmed.split_once("://").map_or("(none)", |(s, _)| s);
        return Err(CanaryError::InvalidNotifyUrl {
            reason: format!("only https:// URLs are accepted, got scheme {scheme:?}"),
        });
    }
    let host = trimmed
        .strip_prefix("https://")
        .unwrap_or_default()
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if host.is_empty() {
        return Err(CanaryError::InvalidNotifyUrl {
            reason: "the URL has no host".into(),
        });
    }
    Ok(())
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

        let (result_covers, canary_cover, canary) =
            service.embed_canary(covers, make_cover(), &embedder, None)?;

        assert_eq!(result_covers.len(), 1);
        assert_eq!(canary.shard.data.len(), 64);
        assert_eq!(canary.shard.index, 5); // total_shards = 5, so canary index = 5
        // The canary went into its own cover.
        assert_ne!(canary_cover.data, Bytes::from(vec![0u8; 1024]));
        Ok(())
    }

    #[test]
    fn embed_canary_does_not_modify_the_distribution_covers() -> TestResult {
        let service = CanaryServiceImpl::new(64, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 1024,
            should_fail: false,
        };
        let original = make_cover();
        let original_data = original.data.clone();
        let covers = vec![original];

        let (result_covers, _canary_cover, _canary) =
            service.embed_canary(covers, make_cover(), &embedder, None)?;

        // The real shard's cover must be untouched — the canary is an
        // (N+1)th shard, not a replacement for one of the N.
        assert_eq!(
            result_covers.first().ok_or("index out of bounds")?.data,
            original_data
        );
        Ok(())
    }

    #[test]
    fn embed_canary_fails_when_the_shards_are_too_short_to_identify() {
        // A canary in a shard this short could not be told apart from an
        // arbitrary payload, so it is refused rather than planted.
        let service = CanaryServiceImpl::new(4, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 1024,
            should_fail: false,
        };

        let result = service.embed_canary(vec![make_cover()], make_cover(), &embedder, None);

        assert!(matches!(
            result,
            Err(CanaryError::ShardTooSmall { shard_size: 4, .. })
        ));
    }

    #[test]
    fn embed_canary_fails_on_empty_covers() {
        let service = CanaryServiceImpl::new(64, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 1024,
            should_fail: false,
        };

        let result = service.embed_canary(vec![], make_cover(), &embedder, None);
        assert!(matches!(result, Err(CanaryError::NoCovers)));
    }

    #[test]
    fn embed_canary_fails_when_the_canary_cover_has_no_capacity() {
        let service = CanaryServiceImpl::new(64, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 0,
            should_fail: false,
        };
        let covers = vec![make_cover()];

        let result = service.embed_canary(covers, make_cover(), &embedder, None);
        assert!(matches!(result, Err(CanaryError::EmbedFailed { .. })));
    }

    #[test]
    fn embed_canary_rejects_a_non_https_notify_url() {
        let service = CanaryServiceImpl::new(64, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 1024,
            should_fail: false,
        };
        let covers = vec![make_cover()];

        let result = service.embed_canary(
            covers,
            make_cover(),
            &embedder,
            Some("http://insecure.example.com/canary".to_owned()),
        );
        assert!(matches!(result, Err(CanaryError::InvalidNotifyUrl { .. })));
    }

    #[test]
    fn embed_canary_accepts_an_https_notify_url() -> TestResult {
        let service = CanaryServiceImpl::new(64, 5);
        let embedder = MockEmbedder {
            capacity_bytes: 1024,
            should_fail: false,
        };
        let covers = vec![make_cover()];

        let (_covers, _canary_cover, canary) = service.embed_canary(
            covers,
            make_cover(),
            &embedder,
            Some("https://example.com/canary".to_owned()),
        )?;
        assert_eq!(
            canary.notify_url.as_deref(),
            Some("https://example.com/canary")
        );
        Ok(())
    }

    #[test]
    fn check_canary_identifies_the_canary_payload() {
        let service = CanaryServiceImpl::new(64, 5);
        let canary_id = Uuid::new_v4();
        let canary = generate_canary_shard(canary_id, 64, 5, None);

        assert!(service.check_canary(&canary.shard.data, canary_id));
    }

    #[test]
    fn check_canary_rejects_a_different_payload() {
        let service = CanaryServiceImpl::new(64, 5);
        let canary_id = Uuid::new_v4();

        assert!(!service.check_canary(&[0u8; 64], canary_id));
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
