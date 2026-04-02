//! ZIP / TAR / TAR.GZ archive handling.
//!
//! Pure domain logic — format detection only. All I/O goes through adapters.

use crate::domain::types::ArchiveFormat;

/// Detect archive format by magic bytes.
///
/// Returns `None` if the format is unrecognised.
#[must_use]
pub fn detect_format(data: &[u8]) -> Option<ArchiveFormat> {
    if data.first() == Some(&0x50) && data.get(1) == Some(&0x4B) {
        // PK (ZIP magic)
        Some(ArchiveFormat::Zip)
    } else if data.first() == Some(&0x1F) && data.get(1) == Some(&0x8B) {
        // Gzip magic → TAR.GZ
        Some(ArchiveFormat::TarGz)
    } else if data.len() >= 263 && data.get(257..262) == Some(b"ustar") {
        // POSIX TAR magic at offset 257
        Some(ArchiveFormat::Tar)
    } else {
        None
    }
}

/// Maximum recursion depth for nested archive unpacking.
pub const MAX_NESTING_DEPTH: u8 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn detect_zip_by_magic() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0];
        assert_eq!(detect_format(&data), Some(ArchiveFormat::Zip));
    }

    #[test]
    fn detect_tar_gz_by_magic() {
        let data = [0x1F, 0x8B, 0, 0];
        assert_eq!(detect_format(&data), Some(ArchiveFormat::TarGz));
    }

    #[test]
    fn detect_tar_by_ustar() -> TestResult {
        let mut data = vec![0u8; 300];
        data.get_mut(257..262)
            .ok_or("slice out of bounds")?
            .copy_from_slice(b"ustar");
        assert_eq!(detect_format(&data), Some(ArchiveFormat::Tar));
        Ok(())
    }

    #[test]
    fn detect_unknown_returns_none() {
        let data = [0xFF, 0xFE, 0x00, 0x01];
        assert_eq!(detect_format(&data), None);
    }

    #[test]
    fn detect_empty_returns_none() {
        assert_eq!(detect_format(&[]), None);
    }
}
