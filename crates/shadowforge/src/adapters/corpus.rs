//! Adapter implementing the [`CorpusIndex`] port for zero-modification
//! steganographic cover selection.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::domain::corpus;
use crate::domain::errors::CorpusError;
use crate::domain::ports::CorpusIndex;
use crate::domain::types::{CorpusEntry, CoverMediaKind, Payload, StegoTechnique};

/// In-memory corpus index backed by a `HashMap<file_hash, CorpusEntry>`.
///
/// Search uses a linear scan with Hamming distance — sufficient for corpora
/// up to ~100 K images. Interior mutability via [`RefCell`] keeps the port
/// trait's `&self` receiver while allowing mutation during `add_to_index`
/// and `build_index`.
pub struct CorpusIndexImpl {
    entries: RefCell<HashMap<[u8; 32], CorpusEntry>>,
}

impl CorpusIndexImpl {
    /// Create an empty corpus index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RefCell::new(HashMap::new()),
        }
    }

    /// Return the number of entries currently in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// Return `true` if the index contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.borrow().is_empty()
    }
}

impl Default for CorpusIndexImpl {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect the cover media kind from a file extension.
fn kind_from_extension(path: &Path) -> Option<CoverMediaKind> {
    let ext = path.extension()?.to_str()?.to_lowercase();
    match ext.as_str() {
        "png" => Some(CoverMediaKind::PngImage),
        "bmp" => Some(CoverMediaKind::BmpImage),
        "jpg" | "jpeg" => Some(CoverMediaKind::JpegImage),
        "gif" => Some(CoverMediaKind::GifImage),
        "wav" => Some(CoverMediaKind::WavAudio),
        _ => None,
    }
}

impl CorpusIndex for CorpusIndexImpl {
    fn search(
        &self,
        payload: &Payload,
        _technique: StegoTechnique,
        max_results: usize,
    ) -> Result<Vec<CorpusEntry>, CorpusError> {
        let entries = self.entries.borrow();
        if entries.is_empty() {
            return Err(CorpusError::NoSuitableCover {
                payload_bytes: payload.len() as u64,
            });
        }

        let payload_pattern = corpus::payload_to_bit_pattern(payload.as_bytes(), None);

        // Score each entry by Hamming distance and collect results
        let mut scored: Vec<(u64, CorpusEntry)> = entries
            .values()
            .map(|entry| {
                let dist = corpus::score_match(&entry.precomputed_bit_pattern, &payload_pattern);
                (dist, entry.clone())
            })
            .collect();

        scored.sort_by_key(|(dist, _)| *dist);
        scored.truncate(max_results);

        if scored.is_empty() {
            return Err(CorpusError::NoSuitableCover {
                payload_bytes: payload.len() as u64,
            });
        }

        Ok(scored.into_iter().map(|(_, entry)| entry).collect())
    }

    fn add_to_index(&self, path: &Path) -> Result<CorpusEntry, CorpusError> {
        let cover_kind = kind_from_extension(path).ok_or_else(|| CorpusError::AddFailed {
            path: path.display().to_string(),
            reason: "unsupported file extension".into(),
        })?;

        let data = std::fs::read(path).map_err(|e| CorpusError::AddFailed {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        let file_hash: [u8; 32] = Sha256::digest(&data).into();
        let bit_pattern = corpus::extract_lsb_pattern(&data);

        let entry = CorpusEntry {
            file_hash,
            path: path.display().to_string(),
            cover_kind,
            precomputed_bit_pattern: bit_pattern,
        };

        self.entries.borrow_mut().insert(file_hash, entry.clone());
        Ok(entry)
    }

    fn build_index(&self, corpus_dir: &Path) -> Result<usize, CorpusError> {
        if !corpus_dir.is_dir() {
            return Err(CorpusError::IndexError {
                reason: format!("{} is not a directory", corpus_dir.display()),
            });
        }

        let mut count = 0usize;
        let entries = std::fs::read_dir(corpus_dir).map_err(|e| CorpusError::IndexError {
            reason: e.to_string(),
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| CorpusError::IndexError {
                reason: e.to_string(),
            })?;
            let path = entry.path();
            if path.is_file()
                && kind_from_extension(&path).is_some()
                && self.add_to_index(&path).is_ok()
            {
                count = count.strict_add(1);
            }
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    use super::*;

    /// Create a minimal 1×1 BMP file with known pixel data.
    fn make_test_bmp(pixel_rgb: [u8; 3]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Minimal 1×1 24-bit BMP
        let mut bmp = Vec::new();
        // BMP header (14 bytes)
        bmp.write_all(b"BM")?;
        let file_size: u32 = 14 + 40 + 4; // header + DIB + 1 pixel (padded to 4 bytes)
        bmp.write_all(&file_size.to_le_bytes())?;
        bmp.write_all(&0u32.to_le_bytes())?; // reserved
        bmp.write_all(&54u32.to_le_bytes())?; // pixel data offset

        // DIB header (40 bytes - BITMAPINFOHEADER)
        bmp.write_all(&40u32.to_le_bytes())?; // header size
        bmp.write_all(&1i32.to_le_bytes())?; // width
        bmp.write_all(&1i32.to_le_bytes())?; // height
        bmp.write_all(&1u16.to_le_bytes())?; // color planes
        bmp.write_all(&24u16.to_le_bytes())?; // bits per pixel
        bmp.write_all(&0u32.to_le_bytes())?; // compression
        bmp.write_all(&4u32.to_le_bytes())?; // image size (padded row)
        bmp.write_all(&2835i32.to_le_bytes())?; // h resolution
        bmp.write_all(&2835i32.to_le_bytes())?; // v resolution
        bmp.write_all(&0u32.to_le_bytes())?; // colors in palette
        bmp.write_all(&0u32.to_le_bytes())?; // important colors

        // Pixel data (BGR, padded to 4 bytes)
        bmp.push(pixel_rgb[2]); // B
        bmp.push(pixel_rgb[1]); // G
        bmp.push(pixel_rgb[0]); // R
        bmp.push(0); // padding

        Ok(bmp)
    }

    #[test]
    fn build_index_counts_files() -> TestResult {
        let dir = tempfile::tempdir()?;
        for i in 0..5 {
            let path = dir.path().join(format!("img_{i}.bmp"));
            std::fs::write(&path, make_test_bmp([i * 50, 0, 0])?)?;
        }

        let index = CorpusIndexImpl::new();
        let count = index.build_index(dir.path())?;
        assert_eq!(count, 5);
        assert_eq!(index.len(), 5);
        Ok(())
    }

    #[test]
    fn build_index_skips_non_image_files() -> TestResult {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("readme.txt"), b"hello")?;
        std::fs::write(dir.path().join("img.bmp"), make_test_bmp([0, 0, 0])?)?;

        let index = CorpusIndexImpl::new();
        let count = index.build_index(dir.path())?;
        assert_eq!(count, 1);
        Ok(())
    }

    #[test]
    fn search_returns_exact_match_first() -> TestResult {
        let dir = tempfile::tempdir()?;
        let target_data = make_test_bmp([0xFF, 0xFF, 0xFF])?;
        let target_path = dir.path().join("target.bmp");
        std::fs::write(&target_path, &target_data)?;

        // Add a different image too
        std::fs::write(dir.path().join("other.bmp"), make_test_bmp([0, 0, 0])?)?;

        let index = CorpusIndexImpl::new();
        index.build_index(dir.path())?;

        // Search with a payload that matches the target's bit pattern
        let target_hash: [u8; 32] = Sha256::digest(&target_data).into();
        let target_entry = index.entries.borrow();
        let expected_pattern = &target_entry
            .get(&target_hash)
            .ok_or("target hash not found in index")?
            .precomputed_bit_pattern;
        let payload = Payload::from_bytes(expected_pattern.to_vec());
        drop(target_entry);

        let results = index.search(&payload, StegoTechnique::LsbImage, 5)?;
        assert!(!results.is_empty());
        // First result should be the exact match
        assert_eq!(
            results.first().ok_or("no search results")?.file_hash,
            target_hash
        );
        Ok(())
    }

    #[test]
    fn search_empty_index_returns_error() {
        let index = CorpusIndexImpl::new();
        let payload = Payload::from_bytes(vec![0x42]);
        let result = index.search(&payload, StegoTechnique::LsbImage, 5);
        assert!(result.is_err());
    }

    #[test]
    fn add_to_index_rejects_unsupported_extension() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("readme.txt");
        std::fs::write(&path, b"not an image")?;

        let index = CorpusIndexImpl::new();
        assert!(index.add_to_index(&path).is_err());
        Ok(())
    }

    #[test]
    fn build_index_rejects_non_directory() -> TestResult {
        let file = tempfile::NamedTempFile::new()?;
        let index = CorpusIndexImpl::new();
        let result = index.build_index(file.path());
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn default_impl() {
        let index = CorpusIndexImpl::default();
        assert!(index.is_empty());
    }
}
