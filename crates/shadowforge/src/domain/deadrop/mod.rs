//! Dead drop mode: platform-aware cover generation for public posting.
//!
//! Produces stego covers optimised for specific platforms. The sender posts
//! publicly and the recipient retrieves via URL — no direct file transfer.

use sha2::{Digest, Sha256};

use crate::domain::types::{PlatformProfile, RetrievalManifest, StegoTechnique};

/// Build a [`RetrievalManifest`] for a dead-drop cover.
///
/// The `stego_bytes` are hashed to produce the integrity digest.
#[must_use]
pub fn build_retrieval_manifest(
    platform: &PlatformProfile,
    retrieval_url: String,
    technique: StegoTechnique,
    stego_bytes: &[u8],
) -> RetrievalManifest {
    let hash = Sha256::digest(stego_bytes);
    let stego_hash = hex::encode(hash);

    RetrievalManifest {
        platform: platform.clone(),
        retrieval_url,
        technique,
        stego_hash,
    }
}

/// Returns `true` if the platform passes images losslessly (no recompression).
#[must_use]
pub const fn platform_is_lossless(platform: &PlatformProfile) -> bool {
    matches!(platform, PlatformProfile::Telegram)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn retrieval_manifest_serialises_to_json() -> TestResult {
        let manifest = build_retrieval_manifest(
            &PlatformProfile::Instagram,
            "https://instagram.com/p/abc123".to_owned(),
            StegoTechnique::LsbImage,
            b"fake stego bytes",
        );

        let json = serde_json::to_string_pretty(&manifest)?;
        assert!(json.contains("Instagram"));
        assert!(json.contains("abc123"));
        assert!(!manifest.stego_hash.is_empty());
        Ok(())
    }

    #[test]
    fn retrieval_manifest_hash_changes_with_content() {
        let m1 = build_retrieval_manifest(
            &PlatformProfile::Twitter,
            "https://x.com/post/1".to_owned(),
            StegoTechnique::LsbImage,
            b"content A",
        );
        let m2 = build_retrieval_manifest(
            &PlatformProfile::Twitter,
            "https://x.com/post/1".to_owned(),
            StegoTechnique::LsbImage,
            b"content B",
        );

        assert_ne!(m1.stego_hash, m2.stego_hash);
    }

    #[test]
    fn telegram_is_lossless() {
        assert!(platform_is_lossless(&PlatformProfile::Telegram));
    }

    #[test]
    fn instagram_is_not_lossless() {
        assert!(!platform_is_lossless(&PlatformProfile::Instagram));
    }

    #[test]
    fn retrieval_manifest_deserialises_roundtrip() -> TestResult {
        let manifest = build_retrieval_manifest(
            &PlatformProfile::Custom {
                quality: 85,
                subsampling: crate::domain::types::ChromaSubsampling::Yuv420,
            },
            "https://example.com/image.png".to_owned(),
            StegoTechnique::LsbImage,
            b"test data",
        );

        let json = serde_json::to_string(&manifest)?;
        let recovered: RetrievalManifest = serde_json::from_str(&json)?;

        assert_eq!(recovered.stego_hash, manifest.stego_hash);
        assert_eq!(recovered.retrieval_url, manifest.retrieval_url);
        Ok(())
    }
}
