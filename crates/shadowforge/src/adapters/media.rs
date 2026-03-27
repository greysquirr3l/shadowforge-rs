//! Image and audio codec adapters for cover media.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use bytes::Bytes;
use hound::{WavReader, WavSpec, WavWriter};
use image::{DynamicImage, ImageFormat};

use crate::domain::errors::MediaError;
use crate::domain::ports::MediaLoader;
use crate::domain::types::{CoverMedia, CoverMediaKind};

// Metadata keys
const KEY_WIDTH: &str = "width";
const KEY_HEIGHT: &str = "height";
const KEY_FORMAT: &str = "format";
const KEY_SAMPLE_RATE: &str = "sample_rate";
const KEY_CHANNELS: &str = "channels";
const KEY_BITS_PER_SAMPLE: &str = "bits_per_sample";
const KEY_PALETTE: &str = "palette";
const KEY_QUANT_TABLES: &str = "quant_tables";

/// Image media loader for PNG/BMP/JPEG/GIF.
///
/// Loads images to raw RGBA8 pixel data stored in `CoverMedia.data`.
/// Metadata includes width, height, format, and format-specific data
/// (palette for GIF, quantization tables for JPEG).
#[derive(Debug, Default)]
pub struct ImageMediaLoader;

impl MediaLoader for ImageMediaLoader {
    fn load(&self, path: &Path) -> Result<CoverMedia, MediaError> {
        // Detect format from extension
        let extension = path
            .extension()
            .and_then(|s| s.to_str())
            .ok_or_else(|| MediaError::UnsupportedFormat {
                extension: "none".to_string(),
            })?;

        let format = match extension.to_lowercase().as_str() {
            "png" => ImageFormat::Png,
            "bmp" => ImageFormat::Bmp,
            "jpg" | "jpeg" => ImageFormat::Jpeg,
            "gif" => ImageFormat::Gif,
            ext => {
                return Err(MediaError::UnsupportedFormat {
                    extension: ext.to_string(),
                })
            }
        };

        // Load image
        let img = image::open(path).map_err(|e| MediaError::DecodeFailed {
            reason: e.to_string(),
        })?;

        let kind = match format {
            ImageFormat::Png => CoverMediaKind::PngImage,
            ImageFormat::Bmp => CoverMediaKind::BmpImage,
            ImageFormat::Jpeg => CoverMediaKind::JpegImage,
            ImageFormat::Gif => CoverMediaKind::GifImage,
            _ => unreachable!(),
        };

        // Convert to RGBA8
        let rgba = img.to_rgba8();
        let (width, height) = rgba.dimensions();

        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert(KEY_WIDTH.to_string(), width.to_string());
        metadata.insert(KEY_HEIGHT.to_string(), height.to_string());
        metadata.insert(KEY_FORMAT.to_string(), format!("{format:?}"));

        // TODO(T13): Extract GIF palette for palette stego
        // TODO(T16): Extract JPEG quant tables for adaptive embedding

        Ok(CoverMedia {
            kind,
            data: Bytes::from(rgba.into_raw()),
            metadata,
        })
    }

    fn save(&self, media: &CoverMedia, path: &Path) -> Result<(), MediaError> {
        // Parse metadata
        let width: u32 = media
            .metadata
            .get(KEY_WIDTH)
            .ok_or_else(|| MediaError::EncodeFailed {
                reason: "missing width metadata".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| MediaError::EncodeFailed {
                reason: e.to_string(),
            })?;

        let height: u32 = media
            .metadata
            .get(KEY_HEIGHT)
            .ok_or_else(|| MediaError::EncodeFailed {
                reason: "missing height metadata".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| MediaError::EncodeFailed {
                reason: e.to_string(),
            })?;

        // Reconstruct image from RGBA8 data
        let img = image::RgbaImage::from_raw(width, height, media.data.to_vec())
            .ok_or_else(|| MediaError::EncodeFailed {
                reason: "invalid image dimensions or data length".to_string(),
            })?;

        let dynamic_img = DynamicImage::ImageRgba8(img);

        // Determine output format from cover media kind
        let format = match media.kind {
            CoverMediaKind::PngImage => ImageFormat::Png,
            CoverMediaKind::BmpImage => ImageFormat::Bmp,
            CoverMediaKind::JpegImage => ImageFormat::Jpeg,
            CoverMediaKind::GifImage => ImageFormat::Gif,
            _ => {
                return Err(MediaError::EncodeFailed {
                    reason: format!("unsupported media kind: {:?}", media.kind),
                })
            }
        };

        // Save image
        dynamic_img
            .save_with_format(path, format)
            .map_err(|e| MediaError::EncodeFailed {
                reason: e.to_string(),
            })?;

        Ok(())
    }
}

/// Audio media loader for WAV files.
///
/// Loads WAV audio to raw i16 LE sample data stored in `CoverMedia.data`.
/// Metadata includes sample_rate, channels, and bits_per_sample.
#[derive(Debug, Default)]
pub struct AudioMediaLoader;

impl MediaLoader for AudioMediaLoader {
    fn load(&self, path: &Path) -> Result<CoverMedia, MediaError> {
        let reader = WavReader::open(path).map_err(|e| MediaError::DecodeFailed {
            reason: e.to_string(),
        })?;

        let spec = reader.spec();

        // Read all samples as i16
        let samples: Vec<i16> = reader
            .into_samples::<i16>()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| MediaError::DecodeFailed {
                reason: e.to_string(),
            })?;

        // Convert samples to little-endian bytes
        let mut data = Vec::with_capacity(samples.len().strict_mul(2));
        for sample in samples {
            data.extend_from_slice(&sample.to_le_bytes());
        }

        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert(KEY_SAMPLE_RATE.to_string(), spec.sample_rate.to_string());
        metadata.insert(KEY_CHANNELS.to_string(), spec.channels.to_string());
        metadata.insert(
            KEY_BITS_PER_SAMPLE.to_string(),
            spec.bits_per_sample.to_string(),
        );

        Ok(CoverMedia {
            kind: CoverMediaKind::WavAudio,
            data: Bytes::from(data),
            metadata,
        })
    }

    fn save(&self, media: &CoverMedia, path: &Path) -> Result<(), MediaError> {
        // Parse metadata
        let sample_rate: u32 = media
            .metadata
            .get(KEY_SAMPLE_RATE)
            .ok_or_else(|| MediaError::EncodeFailed {
                reason: "missing sample_rate metadata".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| MediaError::EncodeFailed {
                reason: e.to_string(),
            })?;

        let channels: u16 = media
            .metadata
            .get(KEY_CHANNELS)
            .ok_or_else(|| MediaError::EncodeFailed {
                reason: "missing channels metadata".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| MediaError::EncodeFailed {
                reason: e.to_string(),
            })?;

        let bits_per_sample: u16 = media
            .metadata
            .get(KEY_BITS_PER_SAMPLE)
            .ok_or_else(|| MediaError::EncodeFailed {
                reason: "missing bits_per_sample metadata".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| MediaError::EncodeFailed {
                reason: e.to_string(),
            })?;

        // Create WAV spec
        let spec = WavSpec {
            channels,
            sample_rate,
            bits_per_sample,
            sample_format: hound::SampleFormat::Int,
        };

        // Create writer
        let file = File::create(path).map_err(|e| MediaError::IoError {
            reason: e.to_string(),
        })?;

        let mut writer =
            WavWriter::new(BufWriter::new(file), spec).map_err(|e| MediaError::EncodeFailed {
                reason: e.to_string(),
            })?;

        // Convert bytes back to i16 samples
        for chunk in media.data.chunks(2) {
            if chunk.len() == 2 {
                let sample = i16::from_le_bytes([chunk[0], chunk[1]]);
                writer
                    .write_sample(sample)
                    .map_err(|e| MediaError::EncodeFailed {
                        reason: e.to_string(),
                    })?;
            }
        }

        writer.finalize().map_err(|e| MediaError::EncodeFailed {
            reason: e.to_string(),
        })?;

        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_image_loader_png_roundtrip() {
        let loader = ImageMediaLoader;
        let dir = tempdir().expect("create tempdir");
        let path = dir.path().join("test.png");

        // Create a 10x10 white RGBA image
        let img = DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            10,
            10,
            image::Rgba([255, 255, 255, 255]),
        ));
        img.save(&path).expect("save test image");

        // Load
        let media = loader.load(&path).expect("load");
        assert_eq!(media.kind, CoverMediaKind::PngImage);
        assert_eq!(media.metadata.get(KEY_WIDTH), Some(&"10".to_string()));
        assert_eq!(media.metadata.get(KEY_HEIGHT), Some(&"10".to_string()));

        // Save
        let out_path = dir.path().join("out.png");
        loader.save(&media, &out_path).expect("save");

        // Reload and verify
        let reloaded = loader.load(&out_path).expect("reload");
        assert_eq!(reloaded.data, media.data);
    }

    #[test]
    fn test_audio_loader_wav_roundtrip() {
        let loader = AudioMediaLoader;
        let dir = tempdir().expect("create tempdir");
        let path = dir.path().join("test.wav");

        // Create a simple WAV with 1000 samples
        let spec = WavSpec {
            channels: 1,
            sample_rate: 44100,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };

        let mut writer = WavWriter::create(&path, spec).expect("create wav");
        for i in 0..1000_i16 {
            writer.write_sample(i).expect("write sample");
        }
        writer.finalize().expect("finalize wav");

        // Load
        let media = loader.load(&path).expect("load");
        assert_eq!(media.kind, CoverMediaKind::WavAudio);
        assert_eq!(
            media.metadata.get(KEY_SAMPLE_RATE),
            Some(&"44100".to_string())
        );
        assert_eq!(media.metadata.get(KEY_CHANNELS), Some(&"1".to_string()));

        // Save
        let out_path = dir.path().join("out.wav");
        loader.save(&media, &out_path).expect("save");

        // Reload and verify
        let reloaded = loader.load(&out_path).expect("reload");
        assert_eq!(reloaded.data, media.data);
    }

    #[test]
    fn test_image_loader_unsupported_format() {
        let loader = ImageMediaLoader;
        let result = loader.load(Path::new("test.xyz"));
        assert!(matches!(
            result,
            Err(MediaError::UnsupportedFormat { .. })
        ));
    }
}
