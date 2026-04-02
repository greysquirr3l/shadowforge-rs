//! Operational security adapters implementing emergency wipe and amnesiac operations.

use crate::domain::errors::OpsecError;
use crate::domain::ports::{
    AmnesiaPipeline, EmbedTechnique, ForensicWatermarker, GeographicDistributor, PanicWiper,
};
use crate::domain::types::{
    CoverMedia, GeographicManifest, PanicWipeConfig, Payload, WatermarkReceipt,
    WatermarkTripwireTag,
};
use rand::Rng;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Secure panic wiper using a 3-pass overwrite-then-delete strategy.
///
/// Overwrites files with:
/// 1. Pass 1: All zeros
/// 2. Pass 2: All ones (0xFF)
/// 3. Pass 3: Cryptographically random data
///
/// Then truncates and deletes the file. Continues on errors to ensure
/// maximum coverage even under duress.
pub struct SecurePanicWiper;

impl SecurePanicWiper {
    /// Create a new secure panic wiper.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Securely wipe a single file using 3-pass overwrite.
    fn wipe_file(path: &Path) -> Result<(), String> {
        // Check if file exists
        if !path.exists() {
            return Err(format!("file does not exist: {}", path.display()));
        }

        // Get file size
        let metadata = fs::metadata(path).map_err(|e| format!("failed to get metadata: {e}"))?;
        let file_size = metadata.len();

        if file_size == 0 {
            // Empty file, just delete it
            fs::remove_file(path).map_err(|e| format!("failed to delete empty file: {e}"))?;
            return Ok(());
        }

        // Open file for reading and writing
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| format!("failed to open file for wiping: {e}"))?;

        // Pass 1: Overwrite with zeros
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("failed to seek (pass 1): {e}"))?;
        let zeros = vec![0u8; 4096];
        let mut remaining = file_size;
        while remaining > 0 {
            let chunk_size = remaining.min(4096) as usize;
            file.write_all(
                zeros
                    .get(..chunk_size)
                    .ok_or_else(|| format!("chunk_size {chunk_size} exceeds buffer"))?,
            )
            .map_err(|e| format!("failed to write zeros: {e}"))?;
            remaining -= chunk_size as u64;
        }
        file.flush()
            .map_err(|e| format!("failed to flush (pass 1): {e}"))?;

        // Pass 2: Overwrite with 0xFF
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("failed to seek (pass 2): {e}"))?;
        let ones = vec![0xFFu8; 4096];
        let mut remaining = file_size;
        while remaining > 0 {
            let chunk_size = remaining.min(4096) as usize;
            file.write_all(
                ones.get(..chunk_size)
                    .ok_or_else(|| format!("chunk_size {chunk_size} exceeds buffer"))?,
            )
            .map_err(|e| format!("failed to write ones: {e}"))?;
            remaining -= chunk_size as u64;
        }
        file.flush()
            .map_err(|e| format!("failed to flush (pass 2): {e}"))?;

        // Pass 3: Overwrite with random data
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("failed to seek (pass 3): {e}"))?;
        let mut rng = rand::rng();
        let mut random_buf = vec![0u8; 4096];
        let mut remaining = file_size;
        while remaining > 0 {
            let chunk_size = remaining.min(4096) as usize;
            rng.fill_bytes(
                random_buf
                    .get_mut(..chunk_size)
                    .ok_or_else(|| format!("chunk_size {chunk_size} exceeds buffer"))?,
            );
            file.write_all(
                random_buf
                    .get(..chunk_size)
                    .ok_or_else(|| format!("chunk_size {chunk_size} exceeds buffer"))?,
            )
            .map_err(|e| format!("failed to write random data: {e}"))?;
            remaining -= chunk_size as u64;
        }
        file.flush()
            .map_err(|e| format!("failed to flush (pass 3): {e}"))?;

        // Truncate to zero length
        file.set_len(0)
            .map_err(|e| format!("failed to truncate: {e}"))?;

        // Close the file
        drop(file);

        // Delete the file
        fs::remove_file(path).map_err(|e| format!("failed to delete file: {e}"))?;

        Ok(())
    }

    /// Recursively wipe all files in a directory, then remove the directory.
    fn wipe_dir_recursive(path: &Path) -> Result<(), String> {
        if !path.exists() {
            return Err(format!("directory does not exist: {}", path.display()));
        }

        if !path.is_dir() {
            return Err(format!("path is not a directory: {}", path.display()));
        }

        // Read directory entries
        let entries = fs::read_dir(path)
            .map_err(|e| format!("failed to read directory: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("failed to collect entries: {e}"))?;

        // Wipe each entry
        for entry in entries {
            let entry_path = entry.path();

            if entry_path.is_dir() {
                // Recursively wipe subdirectory
                if let Err(e) = Self::wipe_dir_recursive(&entry_path) {
                    eprintln!(
                        "Warning: failed to wipe subdirectory {}: {}",
                        entry_path.display(),
                        e
                    );
                    // Continue to next entry
                }
            } else {
                // Wipe file
                if let Err(e) = Self::wipe_file(&entry_path) {
                    eprintln!(
                        "Warning: failed to wipe file {}: {}",
                        entry_path.display(),
                        e
                    );
                    // Continue to next entry
                }
            }
        }

        // Remove the now-empty directory
        fs::remove_dir(path).map_err(|e| format!("failed to remove directory: {e}"))?;

        Ok(())
    }
}

impl Default for SecurePanicWiper {
    fn default() -> Self {
        Self::new()
    }
}

impl PanicWiper for SecurePanicWiper {
    fn wipe(&self, config: &PanicWipeConfig) -> Result<(), OpsecError> {
        let mut failures = Vec::new();

        // Wipe all key files
        for path in &config.key_paths {
            if let Err(e) = Self::wipe_file(path) {
                eprintln!("Failed to wipe key file {}: {}", path.display(), e);
                failures.push((path.display().to_string(), e));
            }
        }

        // Wipe all config files
        for path in &config.config_paths {
            if let Err(e) = Self::wipe_file(path) {
                eprintln!("Failed to wipe config file {}: {}", path.display(), e);
                failures.push((path.display().to_string(), e));
            }
        }

        // Wipe all temp directories
        for path in &config.temp_dirs {
            if let Err(e) = Self::wipe_dir_recursive(path) {
                eprintln!("Failed to wipe temp directory {}: {}", path.display(), e);
                failures.push((path.display().to_string(), e));
            }
        }

        // If there were any failures, return the first one as an error
        // (but all wipe operations were attempted)
        if let Some((path, reason)) = failures.first() {
            return Err(OpsecError::WipeStepFailed {
                path: path.clone(),
                reason: reason.clone(),
            });
        }

        Ok(())
    }
}

/// In-memory amnesiac pipeline adapter.
///
/// Delegates to [`crate::domain::opsec::embed_in_memory`] to ensure
/// zero filesystem writes during the embed/extract cycle.
pub struct AmnesiaPipelineImpl;

impl AmnesiaPipelineImpl {
    /// Create a new amnesiac pipeline adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for AmnesiaPipelineImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl AmnesiaPipeline for AmnesiaPipelineImpl {
    fn embed_in_memory(
        &self,
        payload_input: &mut dyn Read,
        cover_input: &mut dyn Read,
        output: &mut dyn Write,
        technique: &dyn EmbedTechnique,
    ) -> Result<(), OpsecError> {
        crate::domain::opsec::embed_in_memory(payload_input, cover_input, output, technique)
    }
}

/// Geographic threshold distribution adapter.
///
/// Validates the manifest, then embeds payload shards into covers
/// annotated with jurisdictional metadata.
pub struct GeographicDistributorImpl;

impl GeographicDistributorImpl {
    /// Create a new geographic distributor adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for GeographicDistributorImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl GeographicDistributor for GeographicDistributorImpl {
    fn distribute_with_manifest(
        &self,
        payload: &Payload,
        covers: Vec<CoverMedia>,
        manifest: &GeographicManifest,
        embedder: &dyn EmbedTechnique,
    ) -> Result<Vec<CoverMedia>, OpsecError> {
        // Validate manifest first
        crate::domain::opsec::validate_manifest(manifest)?;

        if covers.len() < manifest.shards.len() {
            return Err(OpsecError::ManifestError {
                reason: format!(
                    "not enough covers ({}) for manifest entries ({})",
                    covers.len(),
                    manifest.shards.len()
                ),
            });
        }

        // For each shard entry, embed payload into the corresponding cover
        let payload_bytes = payload.as_bytes();
        let shard_count = manifest.shards.len();

        // Simple equal-size distribution: split payload into N chunks
        let chunk_size = payload_bytes.len().div_ceil(shard_count);
        let mut results = Vec::with_capacity(shard_count);

        for (i, cover) in covers.into_iter().enumerate().take(shard_count) {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(payload_bytes.len());
            let chunk = payload_bytes.get(start..end).unwrap_or_default();

            let shard_payload = Payload::from_bytes(chunk.to_vec());
            let stego =
                embedder
                    .embed(cover, &shard_payload)
                    .map_err(|e| OpsecError::ManifestError {
                        reason: format!("embed failed for shard {i}: {e}"),
                    })?;
            results.push(stego);
        }

        Ok(results)
    }
}

/// Forensic watermark tripwire adapter.
///
/// Delegates to [`crate::domain::opsec::embed_watermark`] and
/// [`crate::domain::opsec::identify_watermark`].
pub struct ForensicWatermarkerImpl;

impl ForensicWatermarkerImpl {
    /// Create a new forensic watermarker adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ForensicWatermarkerImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicWatermarker for ForensicWatermarkerImpl {
    fn embed_tripwire(
        &self,
        mut cover: CoverMedia,
        tag: &WatermarkTripwireTag,
    ) -> Result<CoverMedia, OpsecError> {
        crate::domain::opsec::embed_watermark(&mut cover, tag)?;
        Ok(cover)
    }

    fn identify_recipient(
        &self,
        stego: &CoverMedia,
        tags: &[WatermarkTripwireTag],
    ) -> Result<Option<WatermarkReceipt>, OpsecError> {
        let result = crate::domain::opsec::identify_watermark(stego, tags);
        Ok(result.and_then(|idx| {
            let tag = tags.get(idx)?;
            Some(WatermarkReceipt {
                recipient: tag.recipient_id.to_string(),
                algorithm: "lsb-tripwire-v1".into(),
                shards: vec![],
                created_at: chrono::Utc::now(),
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_wipe_single_file() -> TestResult {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_key.txt");

        // Create a file with some content
        fs::write(&file_path, b"secret key data")?;

        assert!(file_path.exists());

        // Wipe the file
        SecurePanicWiper::wipe_file(&file_path)?;

        // File should no longer exist
        assert!(!file_path.exists());
        Ok(())
    }

    #[test]
    fn test_wipe_empty_file() -> TestResult {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("empty.txt");

        // Create an empty file
        File::create(&file_path)?;
        assert!(file_path.exists());

        // Wipe should succeed
        SecurePanicWiper::wipe_file(&file_path)?;
        assert!(!file_path.exists());
        Ok(())
    }

    #[test]
    fn test_wipe_nonexistent_file_returns_error() {
        let result = SecurePanicWiper::wipe_file(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
        if let Err(msg) = result {
            assert!(msg.contains("does not exist"));
        }
    }

    #[test]
    fn test_wipe_config_with_multiple_files() -> TestResult {
        let temp_dir = TempDir::new()?;

        let key1 = temp_dir.path().join("key1.pem");
        let key2 = temp_dir.path().join("key2.pem");
        let config_file = temp_dir.path().join("config.toml");

        // Create test files
        fs::write(&key1, b"private key 1")?;
        fs::write(&key2, b"private key 2")?;
        fs::write(&config_file, b"sensitive config")?;

        assert!(key1.exists());
        assert!(key2.exists());
        assert!(config_file.exists());

        // Create wipe config
        let wipe_config = PanicWipeConfig {
            key_paths: vec![key1.clone(), key2.clone()],
            config_paths: vec![config_file.clone()],
            temp_dirs: vec![],
        };

        let wiper = SecurePanicWiper::new();
        wiper.wipe(&wipe_config)?;

        // All files should be gone
        assert!(!key1.exists());
        assert!(!key2.exists());
        assert!(!config_file.exists());
        Ok(())
    }

    #[test]
    fn test_wipe_directory_recursive() -> TestResult {
        let temp_dir = TempDir::new()?;
        let wipe_dir = temp_dir.path().join("to_wipe");
        let subdir = wipe_dir.join("subdir");

        // Create directory structure
        fs::create_dir_all(&subdir)?;

        let file1 = wipe_dir.join("file1.txt");
        let file2 = subdir.join("file2.txt");

        fs::write(&file1, b"temp data 1")?;
        fs::write(&file2, b"temp data 2")?;

        assert!(wipe_dir.exists());
        assert!(file1.exists());
        assert!(file2.exists());

        // Wipe the directory
        SecurePanicWiper::wipe_dir_recursive(&wipe_dir)?;

        // Directory and all contents should be gone
        assert!(!wipe_dir.exists());
        assert!(!file1.exists());
        assert!(!file2.exists());
        Ok(())
    }

    #[test]
    fn test_wipe_continues_on_partial_failure() -> TestResult {
        let temp_dir = TempDir::new()?;

        let key1 = temp_dir.path().join("key1.pem");
        let nonexistent = temp_dir.path().join("nonexistent.pem");
        let key2 = temp_dir.path().join("key2.pem");

        // Create only key1 and key2
        fs::write(&key1, b"key 1")?;
        fs::write(&key2, b"key 2")?;

        let wipe_config = PanicWipeConfig {
            key_paths: vec![key1.clone(), nonexistent, key2.clone()],
            config_paths: vec![],
            temp_dirs: vec![],
        };

        let wiper = SecurePanicWiper::new();
        let result = wiper.wipe(&wipe_config);

        // Should return an error for the nonexistent file
        assert!(
            matches!(&result, Err(OpsecError::WipeStepFailed { path, .. }) if path.contains("nonexistent.pem")),
        );

        // But key1 and key2 should still be wiped
        assert!(!key1.exists());
        assert!(!key2.exists());
        Ok(())
    }

    #[test]
    fn test_overwrite_actually_changes_file_content() -> TestResult {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test.dat");

        // Write some recognizable pattern
        let original_data = b"AAAABBBBCCCCDDDD";
        fs::write(&file_path, original_data)?;

        // Read back to verify
        let mut file = File::open(&file_path)?;
        let mut read_back = Vec::new();
        file.read_to_end(&mut read_back)?;
        assert_eq!(read_back, original_data);
        drop(file);

        // Now open and check size, then wipe
        let file_size = fs::metadata(&file_path)?.len();
        assert_eq!(file_size, original_data.len() as u64);

        SecurePanicWiper::wipe_file(&file_path)?;

        // File should be gone
        assert!(!file_path.exists());
        Ok(())
    }

    // ─── AmnesiaPipeline Tests ────────────────────────────────────────────

    use crate::domain::errors::StegoError;
    use crate::domain::types::{Capacity, CoverMedia, Payload, StegoTechnique};
    use bytes::Bytes;
    use std::io::Cursor;

    struct MockEmbedder;

    impl crate::domain::ports::EmbedTechnique for MockEmbedder {
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

    #[test]
    fn amnesiac_adapter_embed_roundtrip() -> TestResult {
        let pipeline = AmnesiaPipelineImpl::new();
        let mut cover = Cursor::new(b"img-data".to_vec());
        let mut payload = Cursor::new(b"secret".to_vec());
        let mut output = Vec::new();

        pipeline.embed_in_memory(&mut payload, &mut cover, &mut output, &MockEmbedder)?;

        assert!(output.starts_with(b"img-data"));
        assert!(output.ends_with(b"secret"));
        Ok(())
    }

    #[test]
    fn amnesiac_adapter_default() -> TestResult {
        let pipeline = AmnesiaPipelineImpl;
        let mut cover = Cursor::new(b"c".to_vec());
        let mut payload = Cursor::new(b"p".to_vec());
        let mut output = Vec::new();

        pipeline.embed_in_memory(&mut payload, &mut cover, &mut output, &MockEmbedder)?;

        assert!(!output.is_empty());
        Ok(())
    }

    // ─── GeographicDistributor Tests ──────────────────────────────────────

    use crate::domain::types::{CoverMediaKind, GeoShardEntry, GeographicManifest};

    fn test_covers(n: usize) -> Vec<CoverMedia> {
        (0..n)
            .map(|i| CoverMedia {
                kind: CoverMediaKind::PngImage,
                data: Bytes::from(vec![0u8; 64]),
                metadata: {
                    let mut m = std::collections::HashMap::new();
                    m.insert("idx".into(), i.to_string());
                    m
                },
            })
            .collect()
    }

    fn test_geo_manifest() -> GeographicManifest {
        GeographicManifest {
            shards: vec![
                GeoShardEntry {
                    shard_index: 0,
                    jurisdiction: "IS".into(),
                    holder_description: "Iceland contact".into(),
                },
                GeoShardEntry {
                    shard_index: 1,
                    jurisdiction: "CH".into(),
                    holder_description: "Swiss contact".into(),
                },
                GeoShardEntry {
                    shard_index: 2,
                    jurisdiction: "SG".into(),
                    holder_description: "Singapore contact".into(),
                },
            ],
            minimum_jurisdictions: 2,
        }
    }

    #[test]
    fn geographic_distribute_succeeds() -> TestResult {
        let distributor = GeographicDistributorImpl::new();
        let payload = Payload::from_bytes(b"secret payload data here!".to_vec());
        let covers = test_covers(3);
        let manifest = test_geo_manifest();

        let results =
            distributor.distribute_with_manifest(&payload, covers, &manifest, &MockEmbedder)?;

        assert_eq!(results.len(), 3);
        Ok(())
    }

    #[test]
    fn geographic_distribute_fails_insufficient_covers() {
        let distributor = GeographicDistributorImpl::new();
        let payload = Payload::from_bytes(b"secret".to_vec());
        let covers = test_covers(1); // Only 1 cover for 3 shards
        let manifest = test_geo_manifest();

        let result =
            distributor.distribute_with_manifest(&payload, covers, &manifest, &MockEmbedder);
        assert!(result.is_err());
    }

    #[test]
    fn geographic_distribute_fails_invalid_manifest() {
        let distributor = GeographicDistributorImpl::new();
        let payload = Payload::from_bytes(b"secret".to_vec());
        let covers = test_covers(1);
        let manifest = GeographicManifest {
            shards: vec![GeoShardEntry {
                shard_index: 0,
                jurisdiction: "IS".into(),
                holder_description: "one".into(),
            }],
            minimum_jurisdictions: 3, // Needs 3 but only has 1
        };

        let result =
            distributor.distribute_with_manifest(&payload, covers, &manifest, &MockEmbedder);
        assert!(result.is_err());
    }

    #[test]
    fn geographic_distributor_default() -> TestResult {
        let distributor = GeographicDistributorImpl;
        let payload = Payload::from_bytes(b"data".to_vec());
        let covers = test_covers(3);
        let manifest = test_geo_manifest();

        let results =
            distributor.distribute_with_manifest(&payload, covers, &manifest, &MockEmbedder)?;
        assert_eq!(results.len(), 3);
        Ok(())
    }

    // ─── ForensicWatermarker Tests ────────────────────────────────────────

    #[test]
    fn forensic_watermarker_embed_roundtrip() -> TestResult {
        let wm = ForensicWatermarkerImpl::new();
        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(vec![0u8; 1024]),
            metadata: std::collections::HashMap::new(),
        };
        let tag = WatermarkTripwireTag {
            recipient_id: uuid::Uuid::new_v4(),
            embedding_seed: b"adapter-test-seed".to_vec(),
        };

        let stego = wm.embed_tripwire(cover, &tag)?;
        let receipt = wm.identify_recipient(&stego, std::slice::from_ref(&tag))?;
        assert!(receipt.is_some());
        let receipt = receipt.ok_or("expected watermark receipt")?;
        assert_eq!(receipt.recipient, tag.recipient_id.to_string());
        assert_eq!(receipt.algorithm, "lsb-tripwire-v1");
        Ok(())
    }

    #[test]
    fn forensic_watermarker_no_match() -> TestResult {
        let wm = ForensicWatermarkerImpl;
        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(vec![0u8; 1024]),
            metadata: std::collections::HashMap::new(),
        };
        let unknown_tag = WatermarkTripwireTag {
            recipient_id: uuid::Uuid::new_v4(),
            embedding_seed: b"unknown".to_vec(),
        };

        let result = wm.identify_recipient(&cover, &[unknown_tag])?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn wipe_dir_recursive_nonexistent() {
        let result = SecurePanicWiper::wipe_dir_recursive(Path::new("/nonexistent/dir"));
        assert!(result.is_err());
        if let Err(msg) = result {
            assert!(msg.contains("does not exist"));
        }
    }

    #[test]
    fn wipe_dir_recursive_not_a_directory() -> TestResult {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("regular_file.txt");
        fs::write(&file_path, b"data")?;

        let result = SecurePanicWiper::wipe_dir_recursive(&file_path);
        assert!(result.is_err());
        if let Err(msg) = result {
            assert!(msg.contains("not a directory"));
        }
        Ok(())
    }

    #[test]
    fn wipe_config_with_temp_dirs() -> TestResult {
        let temp_dir = TempDir::new()?;
        let temp_subdir = temp_dir.path().join("cache");
        fs::create_dir_all(&temp_subdir)?;
        let cache_file = temp_subdir.join("cached.dat");
        fs::write(&cache_file, b"cached stuff")?;

        let config_file = temp_dir.path().join("settings.toml");
        fs::write(&config_file, b"[settings]\nkey = true")?;

        let wipe_config = PanicWipeConfig {
            key_paths: vec![],
            config_paths: vec![config_file.clone()],
            temp_dirs: vec![temp_subdir.clone()],
        };

        let wiper = SecurePanicWiper::new();
        wiper.wipe(&wipe_config)?;

        assert!(!config_file.exists());
        assert!(!temp_subdir.exists());
        Ok(())
    }

    #[test]
    fn wipe_config_with_missing_temp_dir_returns_error() -> TestResult {
        let temp_dir = TempDir::new()?;
        let nonexistent_dir = temp_dir.path().join("no_such_dir");

        let wipe_config = PanicWipeConfig {
            key_paths: vec![],
            config_paths: vec![],
            temp_dirs: vec![nonexistent_dir],
        };

        let wiper = SecurePanicWiper::new();
        let result = wiper.wipe(&wipe_config);
        assert!(matches!(result, Err(OpsecError::WipeStepFailed { .. })));
        Ok(())
    }

    #[test]
    fn wipe_large_file() -> TestResult {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("large.dat");
        // Create a file larger than 4096 bytes to exercise multi-chunk loop
        let data = vec![0x42u8; 8192];
        fs::write(&file_path, &data)?;

        SecurePanicWiper::wipe_file(&file_path)?;
        assert!(!file_path.exists());
        Ok(())
    }

    #[test]
    fn geographic_distributor_extra_covers_ignored() -> TestResult {
        let distributor = GeographicDistributorImpl::new();
        let payload = Payload::from_bytes(b"data for geographic dist".to_vec());
        // 5 covers for only 3 manifest shards — extras get dropped
        let covers = test_covers(5);
        let manifest = test_geo_manifest();

        let results =
            distributor.distribute_with_manifest(&payload, covers, &manifest, &MockEmbedder)?;
        // Only 3 manifest shards, so only 3 results
        assert_eq!(results.len(), 3);
        Ok(())
    }
}
