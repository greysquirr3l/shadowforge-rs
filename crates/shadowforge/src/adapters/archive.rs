//! Adapter implementing the [`ArchiveHandler`] port for ZIP, TAR, and TAR.GZ.

use std::io::{Cursor, Read, Write};

use bytes::Bytes;

use crate::domain::archive::{MAX_NESTING_DEPTH, detect_format};
use crate::domain::errors::ArchiveError;
use crate::domain::ports::ArchiveHandler;
use crate::domain::types::ArchiveFormat;

/// Concrete [`ArchiveHandler`] implementation using in-memory buffers.
pub struct ArchiveHandlerImpl;

impl Default for ArchiveHandlerImpl {
    fn default() -> Self {
        Self
    }
}

impl ArchiveHandlerImpl {
    /// Create a new archive handler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ArchiveHandler for ArchiveHandlerImpl {
    fn pack(&self, files: &[(&str, &[u8])], format: ArchiveFormat) -> Result<Bytes, ArchiveError> {
        match format {
            ArchiveFormat::Zip => pack_zip(files),
            ArchiveFormat::Tar => pack_tar(files),
            ArchiveFormat::TarGz => pack_tar_gz(files),
        }
    }

    fn unpack(
        &self,
        archive: &[u8],
        format: ArchiveFormat,
    ) -> Result<Vec<(String, Bytes)>, ArchiveError> {
        unpack_recursive(archive, format, 0)
    }
}

fn pack_zip(files: &[(&str, &[u8])]) -> Result<Bytes, ArchiveError> {
    let buf = Vec::new();
    let cursor = Cursor::new(buf);
    let mut writer = zip::ZipWriter::new(cursor);

    for &(name, data) in files {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer
            .start_file(name, options)
            .map_err(|e| ArchiveError::PackFailed {
                reason: e.to_string(),
            })?;
        writer
            .write_all(data)
            .map_err(|e| ArchiveError::PackFailed {
                reason: e.to_string(),
            })?;
    }

    let cursor = writer.finish().map_err(|e| ArchiveError::PackFailed {
        reason: e.to_string(),
    })?;
    Ok(Bytes::from(cursor.into_inner()))
}

fn pack_tar(files: &[(&str, &[u8])]) -> Result<Bytes, ArchiveError> {
    let buf = Vec::new();
    let mut builder = tar::Builder::new(buf);

    for &(name, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, data)
            .map_err(|e| ArchiveError::PackFailed {
                reason: e.to_string(),
            })?;
    }

    let buf = builder.into_inner().map_err(|e| ArchiveError::PackFailed {
        reason: e.to_string(),
    })?;
    Ok(Bytes::from(buf))
}

fn pack_tar_gz(files: &[(&str, &[u8])]) -> Result<Bytes, ArchiveError> {
    let buf = Vec::new();
    let encoder = flate2::write::GzEncoder::new(buf, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);

    for &(name, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, data)
            .map_err(|e| ArchiveError::PackFailed {
                reason: e.to_string(),
            })?;
    }

    let encoder = builder.into_inner().map_err(|e| ArchiveError::PackFailed {
        reason: e.to_string(),
    })?;
    let buf = encoder.finish().map_err(|e| ArchiveError::PackFailed {
        reason: e.to_string(),
    })?;
    Ok(Bytes::from(buf))
}

fn unpack_recursive(
    archive: &[u8],
    format: ArchiveFormat,
    depth: u8,
) -> Result<Vec<(String, Bytes)>, ArchiveError> {
    let entries = match format {
        ArchiveFormat::Zip => unpack_zip(archive)?,
        ArchiveFormat::Tar => unpack_tar(archive)?,
        ArchiveFormat::TarGz => unpack_tar_gz(archive)?,
    };

    if depth >= MAX_NESTING_DEPTH {
        return Ok(entries);
    }

    // Check for nested archives
    let mut result = Vec::new();
    for (name, data) in entries {
        if let Some(nested_format) = detect_format(&data) {
            match unpack_recursive(&data, nested_format, depth.strict_add(1)) {
                Ok(nested_entries) => {
                    for (nested_name, nested_data) in nested_entries {
                        result.push((format!("{name}/{nested_name}"), nested_data));
                    }
                }
                Err(_) => {
                    // Not actually a valid archive, treat as regular file
                    result.push((name, data));
                }
            }
        } else {
            result.push((name, data));
        }
    }

    Ok(result)
}

fn unpack_zip(archive: &[u8]) -> Result<Vec<(String, Bytes)>, ArchiveError> {
    let cursor = Cursor::new(archive);
    let mut reader = zip::ZipArchive::new(cursor).map_err(|e| ArchiveError::UnpackFailed {
        reason: e.to_string(),
    })?;

    let mut entries = Vec::new();
    for i in 0..reader.len() {
        let mut file = reader.by_index(i).map_err(|e| ArchiveError::UnpackFailed {
            reason: e.to_string(),
        })?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| ArchiveError::UnpackFailed {
                reason: e.to_string(),
            })?;
        entries.push((name, Bytes::from(data)));
    }

    Ok(entries)
}

fn unpack_tar(archive: &[u8]) -> Result<Vec<(String, Bytes)>, ArchiveError> {
    let cursor = Cursor::new(archive);
    let mut reader = tar::Archive::new(cursor);

    let mut entries = Vec::new();
    for entry_result in reader.entries().map_err(|e| ArchiveError::UnpackFailed {
        reason: e.to_string(),
    })? {
        let mut entry = entry_result.map_err(|e| ArchiveError::UnpackFailed {
            reason: e.to_string(),
        })?;
        let path = entry
            .path()
            .map_err(|e| ArchiveError::UnpackFailed {
                reason: e.to_string(),
            })?
            .to_string_lossy()
            .to_string();
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|e| ArchiveError::UnpackFailed {
                reason: e.to_string(),
            })?;
        if !data.is_empty() {
            entries.push((path, Bytes::from(data)));
        }
    }

    Ok(entries)
}

fn unpack_tar_gz(archive: &[u8]) -> Result<Vec<(String, Bytes)>, ArchiveError> {
    let cursor = Cursor::new(archive);
    let decoder = flate2::read::GzDecoder::new(cursor);
    let mut reader = tar::Archive::new(decoder);

    let mut entries = Vec::new();
    for entry_result in reader.entries().map_err(|e| ArchiveError::UnpackFailed {
        reason: e.to_string(),
    })? {
        let mut entry = entry_result.map_err(|e| ArchiveError::UnpackFailed {
            reason: e.to_string(),
        })?;
        let path = entry
            .path()
            .map_err(|e| ArchiveError::UnpackFailed {
                reason: e.to_string(),
            })?
            .to_string_lossy()
            .to_string();
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|e| ArchiveError::UnpackFailed {
                reason: e.to_string(),
            })?;
        if !data.is_empty() {
            entries.push((path, Bytes::from(data)));
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn zip_round_trip() -> TestResult {
        let handler = ArchiveHandlerImpl::new();
        let files = vec![
            ("hello.txt", b"Hello, world!" as &[u8]),
            ("data.bin", &[0xDE, 0xAD, 0xBE, 0xEF]),
        ];
        let packed = handler
            .pack(&files, ArchiveFormat::Zip)
            ?;
        let unpacked = handler
            .unpack(&packed, ArchiveFormat::Zip)
            ?;

        assert_eq!(unpacked.len(), 2);
        assert_eq!(unpacked.first().ok_or("index out of bounds")?.0, "hello.txt");
        assert_eq!(unpacked.first().ok_or("index out of bounds")?.1.as_ref(), b"Hello, world!");
        assert_eq!(unpacked.get(1).ok_or("index out of bounds")?.0, "data.bin");
        assert_eq!(unpacked.get(1).ok_or("index out of bounds")?.1.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        Ok(())
}

    #[test]
    fn tar_round_trip() -> TestResult {
        let handler = ArchiveHandlerImpl::new();
        let files = vec![
            ("file_a.txt", b"AAA" as &[u8]),
            ("file_b.txt", b"BBB" as &[u8]),
        ];
        let packed = handler
            .pack(&files, ArchiveFormat::Tar)
            ?;
        let unpacked = handler
            .unpack(&packed, ArchiveFormat::Tar)
            ?;

        assert_eq!(unpacked.len(), 2);
        assert_eq!(unpacked.first().ok_or("index out of bounds")?.1.as_ref(), b"AAA");
        assert_eq!(unpacked.get(1).ok_or("index out of bounds")?.1.as_ref(), b"BBB");
        Ok(())
}

    #[test]
    fn tar_gz_round_trip() -> TestResult {
        let handler = ArchiveHandlerImpl::new();
        let files = vec![("compressed.txt", b"This is compressed" as &[u8])];
        let packed = handler
            .pack(&files, ArchiveFormat::TarGz)
            ?;
        let unpacked = handler
            .unpack(&packed, ArchiveFormat::TarGz)
            ?;

        assert_eq!(unpacked.len(), 1);
        assert_eq!(unpacked.first().ok_or("index out of bounds")?.1.as_ref(), b"This is compressed");
        Ok(())
}

    #[test]
    fn nested_zip_in_tar() -> TestResult {
        let handler = ArchiveHandlerImpl::new();

        // Create inner ZIP
        let inner_files = vec![("inner.txt", b"nested file content" as &[u8])];
        let inner_zip = handler
            .pack(&inner_files, ArchiveFormat::Zip)
            ?;

        // Create outer TAR containing the ZIP
        let outer_files = vec![("nested.zip", inner_zip.as_ref())];
        let outer_tar = handler
            .pack(&outer_files, ArchiveFormat::Tar)
            ?;

        // Unpack with nesting
        let unpacked = handler
            .unpack(&outer_tar, ArchiveFormat::Tar)
            ?;

        // Should find the nested file with prefixed path
        assert_eq!(unpacked.len(), 1);
        assert_eq!(unpacked.first().ok_or("index out of bounds")?.0, "nested.zip/inner.txt");
        assert_eq!(unpacked.first().ok_or("index out of bounds")?.1.as_ref(), b"nested file content");
        Ok(())
}

    #[test]
    fn format_detection_from_packed() -> TestResult {
        let handler = ArchiveHandlerImpl::new();
        let files = vec![("test.txt", b"x" as &[u8])];

        let zip = handler.pack(&files, ArchiveFormat::Zip)?;
        let tar_gz = handler.pack(&files, ArchiveFormat::TarGz)?;

        assert_eq!(detect_format(&zip), Some(ArchiveFormat::Zip));
        assert_eq!(detect_format(&tar_gz), Some(ArchiveFormat::TarGz));
        Ok(())
}
}
