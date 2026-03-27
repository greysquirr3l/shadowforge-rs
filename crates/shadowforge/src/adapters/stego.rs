//! Steganography technique adapters implementing `EmbedTechnique` port.

use crate::domain::errors::StegoError;
use crate::domain::ports::{EmbedTechnique, ExtractTechnique, PdfProcessor};
use crate::domain::types::{Capacity, CoverMedia, CoverMediaKind, Payload, StegoTechnique};

/// PDF content-stream LSB steganography adapter.
///
/// Wraps the `PdfProcessor`'s content-stream embedding methods to implement
/// the `EmbedTechnique` trait.
pub struct PdfContentStreamLsb {
    processor: Box<dyn PdfProcessor>,
}

impl PdfContentStreamLsb {
    /// Create a new PDF content-stream LSB embedder.
    #[must_use]
    pub fn new(processor: Box<dyn PdfProcessor>) -> Self {
        Self { processor }
    }
}

impl EmbedTechnique for PdfContentStreamLsb {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfContentStream
    }

    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
        // Check if cover is a PDF
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF content-stream LSB requires PdfDocument, got {:?}", cover.kind),
            });
        }

        // TODO(T10): Implement capacity estimation for content-stream LSB
        // For now, return a conservative estimate based on typical PDF content streams
        // Real implementation would parse the PDF and count numeric tokens
        Ok(Capacity {
            bytes: 1024, // Conservative estimate
            technique: StegoTechnique::PdfContentStream,
        })
    }

    fn embed(&self, cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF content-stream LSB requires PdfDocument, got {:?}", cover.kind),
            });
        }

        self.processor
            .embed_in_content_stream(cover, payload)
            .map_err(|e| StegoError::MalformedCoverData {
                reason: format!("embed failed: {e}"),
            })
    }
}

impl ExtractTechnique for PdfContentStreamLsb {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfContentStream
    }

    fn extract(&self, cover: &CoverMedia) -> Result<Payload, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF content-stream LSB requires PdfDocument, got {:?}", cover.kind),
            });
        }

        self.processor
            .extract_from_content_stream(cover)
            .map_err(|e| StegoError::IntegrityCheckFailed {
                reason: format!("extract failed: {e}"),
            })
    }
}

/// PDF XMP metadata steganography adapter.
///
/// Wraps the `PdfProcessor`'s metadata embedding methods to implement
/// the `EmbedTechnique` trait.
pub struct PdfMetadataEmbed {
    processor: Box<dyn PdfProcessor>,
}

impl PdfMetadataEmbed {
    /// Create a new PDF metadata embedder.
    #[must_use]
    pub fn new(processor: Box<dyn PdfProcessor>) -> Self {
        Self { processor }
    }
}

impl EmbedTechnique for PdfMetadataEmbed {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfMetadata
    }

    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF metadata embedding requires PdfDocument, got {:?}", cover.kind),
            });
        }

        // XMP metadata can hold large base64-encoded payloads
        // Base64 encoding adds ~33% overhead
        Ok(Capacity {
            bytes: 1_000_000, // XMP can hold very large payloads
            technique: StegoTechnique::PdfMetadata,
        })
    }

    fn embed(&self, cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF metadata embedding requires PdfDocument, got {:?}", cover.kind),
            });
        }

        self.processor
            .embed_in_metadata(cover, payload)
            .map_err(|e| StegoError::MalformedCoverData {
                reason: format!("embed failed: {e}"),
            })
    }
}

impl ExtractTechnique for PdfMetadataEmbed {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfMetadata
    }

    fn extract(&self, cover: &CoverMedia) -> Result<Payload, StegoError> {
        if cover.kind != CoverMediaKind::PdfDocument {
            return Err(StegoError::UnsupportedCoverType {
                reason: format!("PDF metadata embedding requires PdfDocument, got {:?}", cover.kind),
            });
        }

        self.processor
            .extract_from_metadata(cover)
            .map_err(|e| StegoError::IntegrityCheckFailed {
                reason: format!("extract failed: {e}"),
            })
    }
}

/// LSB image steganography adapter for PNG/BMP.
///
/// Embeds payload in the least significant bits of RGB channels only
/// (alpha channel is untouched). Header encodes 32-bit big-endian payload length.
#[derive(Debug, Default)]
pub struct LsbImage;

impl LsbImage {
    /// Create a new LSB image embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EmbedTechnique for LsbImage {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::LsbImage
    }

    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
        // Only PNG and BMP are supported
        match cover.kind {
            CoverMediaKind::PngImage | CoverMediaKind::BmpImage => {}
            _ => {
                return Err(StegoError::UnsupportedCoverType {
                    reason: format!("LSB image requires PNG or BMP, got {:?}", cover.kind),
                })
            }
        }

        // Parse dimensions from metadata
        let width: u32 = cover
            .metadata
            .get("width")
            .ok_or_else(|| StegoError::MalformedCoverData {
                reason: "missing width metadata".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| StegoError::MalformedCoverData {
                reason: format!("invalid width: {e}"),
            })?;

        let height: u32 = cover
            .metadata
            .get("height")
            .ok_or_else(|| StegoError::MalformedCoverData {
                reason: "missing height metadata".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| StegoError::MalformedCoverData {
                reason: format!("invalid height: {e}"),
            })?;

        let pixel_count = width
            .checked_mul(height)
            .ok_or_else(|| StegoError::MalformedCoverData {
                reason: "pixel count overflow".to_string(),
            })?;

        // Capacity: 3 bits per pixel (R, G, B), minus 32 bits for header
        // = (pixel_count * 3 - 32) / 8 bytes
        let bits = pixel_count
            .checked_mul(3)
            .and_then(|b| b.checked_sub(32))
            .ok_or_else(|| StegoError::MalformedCoverData {
                reason: "capacity calculation overflow".to_string(),
            })?;

        let bytes = u64::from(bits / 8);

        Ok(Capacity {
            bytes,
            technique: StegoTechnique::LsbImage,
        })
    }

    fn embed(&self, mut cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
        // Check cover type
        match cover.kind {
            CoverMediaKind::PngImage | CoverMediaKind::BmpImage => {}
            _ => {
                return Err(StegoError::UnsupportedCoverType {
                    reason: format!("LSB image requires PNG or BMP, got {:?}", cover.kind),
                })
            }
        }

        // Check capacity
        let cap = self.capacity(&cover)?;
        let payload_len = payload.as_bytes().len() as u64;
        if payload_len > cap.bytes {
            return Err(StegoError::PayloadTooLarge {
                needed: payload_len,
                available: cap.bytes,
            });
        }

        // Check that payload length fits in 32-bit header
        if payload_len > u64::from(u32::MAX) {
            return Err(StegoError::PayloadTooLarge {
                needed: payload_len,
                available: u64::from(u32::MAX),
            });
        }

        // Get mutable access to pixel data
        let data = cover.data.to_vec();
        let mut pixels = data;

        // Embed 32-bit big-endian payload length in first 32 LSBs
        #[expect(clippy::cast_possible_truncation, reason = "checked above: payload_len <= u32::MAX")]
        let len_bytes = (payload_len as u32).to_be_bytes();
        for (byte_idx, byte) in len_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let pixel_idx = byte_idx * 8 + bit_idx;

                // RGB only, skip alpha (every 4th byte)
                let channel_idx = pixel_idx / 3;
                let rgb_offset = pixel_idx % 3;
                let byte_pos = channel_idx * 4 + rgb_offset;

                pixels[byte_pos] = (pixels[byte_pos] & 0xFE) | bit;
            }
        }

        // Embed payload bits starting after header (32 bits)
        let payload_bytes = payload.as_bytes();
        for (byte_idx, byte) in payload_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let pixel_idx = 32 + byte_idx * 8 + bit_idx;

                // RGB only, skip alpha
                let channel_idx = pixel_idx / 3;
                let rgb_offset = pixel_idx % 3;
                let byte_pos = channel_idx * 4 + rgb_offset;

                pixels[byte_pos] = (pixels[byte_pos] & 0xFE) | bit;
            }
        }

        cover.data = pixels.into();
        Ok(cover)
    }
}

impl ExtractTechnique for LsbImage {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::LsbImage
    }

    fn extract(&self, cover: &CoverMedia) -> Result<Payload, StegoError> {
        // Check cover type
        match cover.kind {
            CoverMediaKind::PngImage | CoverMediaKind::BmpImage => {}
            _ => {
                return Err(StegoError::UnsupportedCoverType {
                    reason: format!("LSB image requires PNG or BMP, got {:?}", cover.kind),
                })
            }
        }

        let pixels = cover.data.as_ref();

        // Extract 32-bit big-endian payload length from first 32 LSBs
        let mut len_bytes = [0u8; 4];
        for (byte_idx, len_byte) in len_bytes.iter_mut().enumerate() {
            for bit_idx in 0..8 {
                let pixel_idx = byte_idx * 8 + bit_idx;

                // RGB only, skip alpha
                let channel_idx = pixel_idx / 3;
                let rgb_offset = pixel_idx % 3;
                let byte_pos = channel_idx * 4 + rgb_offset;

                let bit = pixels[byte_pos] & 1;
                *len_byte |= bit << (7 - bit_idx);
            }
        }

        let payload_len = u32::from_be_bytes(len_bytes) as usize;

        // Extract payload bits
        let mut payload_bytes = vec![0u8; payload_len];
        for (byte_idx, payload_byte) in payload_bytes.iter_mut().enumerate() {
            for bit_idx in 0..8 {
                let pixel_idx = 32 + byte_idx * 8 + bit_idx;

                // RGB only, skip alpha
                let channel_idx = pixel_idx / 3;
                let rgb_offset = pixel_idx % 3;
                let byte_pos = channel_idx * 4 + rgb_offset;

                let bit = pixels[byte_pos] & 1;
                *payload_byte |= bit << (7 - bit_idx);
            }
        }

        Ok(Payload::from_bytes(payload_bytes))
    }
}

/// DCT-based JPEG steganography adapter (STUB).
///
/// **NOT YET IMPLEMENTED**: Requires a pure-Rust JPEG library that exposes
/// DCT coefficients without unsafe code. Current Rust JPEG libraries either:
/// - Decode to pixels only (jpeg-decoder, image crate)
/// - Require unsafe bindings (mozjpeg-sys, libjpeg-turbo-sys)
///
/// TODO(T12): Implement DCT coefficient access and modification:
/// - Parse JPEG to access non-zero AC DCT coefficients
/// - Embed payload in LSBs of coefficients (skip DC and zeros)
/// - Preserve quantization and Huffman tables
/// - Re-encode JPEG with modified coefficients
#[derive(Debug, Default)]
pub struct DctJpeg;

impl DctJpeg {
    /// Create a new DCT JPEG embedder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EmbedTechnique for DctJpeg {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::DctJpeg
    }

    fn capacity(&self, _cover: &CoverMedia) -> Result<Capacity, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "DCT JPEG steganography not yet implemented (requires DCT coefficient access)"
                .to_string(),
        })
    }

    fn embed(&self, _cover: CoverMedia, _payload: &Payload) -> Result<CoverMedia, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "DCT JPEG steganography not yet implemented (requires DCT coefficient access)"
                .to_string(),
        })
    }
}

impl ExtractTechnique for DctJpeg {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::DctJpeg
    }

    fn extract(&self, _cover: &CoverMedia) -> Result<Payload, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: "DCT JPEG steganography not yet implemented (requires DCT coefficient access)"
                .to_string(),
        })
    }
}

// TODO(T11): Implement PdfPageStegoService after LsbImage is available
// This service will:
// - Render PDF pages to PNG images
// - RS-encode payload into N shards (N = page count)
// - Embed one shard per page using LsbImage
// - Rebuild PDF from stego pages

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::pdf::PdfProcessorImpl;
    use lopdf::{dictionary, Document, Object};

    fn create_test_pdf() -> Vec<u8> {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let page_id = doc.new_object_id();

        doc.objects.insert(
            page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((page_id.0 + 1, 0)),
            }),
        );

        // Content stream with many numeric values
        let content =
            b"BT\n/F1 12 Tf\n100 700 Td\n(Test) Tj\n200 650 Td\n(PDF) Tj\nET\n1 0 0 1 0 0 cm\n";
        doc.add_object(lopdf::Stream::new(dictionary! {}, content.to_vec()));

        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_id)],
                "Count" => 1,
            }),
        );

        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(pages_id),
        });

        doc.trailer.set("Root", Object::Reference(catalog_id));

        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).expect("save test PDF");
        bytes
    }

    #[test]
    fn test_pdf_content_stream_lsb_roundtrip() {
        let processor = Box::new(PdfProcessorImpl::default());
        let embedder = PdfContentStreamLsb::new(processor);

        let pdf_bytes = create_test_pdf();
        let cover = CoverMedia {
            kind: CoverMediaKind::PdfDocument,
            data: pdf_bytes.into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![0xAB]); // 1 byte

        // Embed
        let stego = embedder.embed(cover, &payload).expect("embed");

        // Extract
        let extracted = embedder.extract(&stego).expect("extract");
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn test_pdf_metadata_embed_roundtrip() {
        let processor = Box::new(PdfProcessorImpl::default());
        let embedder = PdfMetadataEmbed::new(processor);

        let pdf_bytes = create_test_pdf();
        let cover = CoverMedia {
            kind: CoverMediaKind::PdfDocument,
            data: pdf_bytes.into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![1, 2, 3, 4, 5]); // 5 bytes

        // Embed
        let stego = embedder.embed(cover, &payload).expect("embed");

        // Extract
        let extracted = embedder.extract(&stego).expect("extract");
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn test_unsupported_cover_type() {
        let processor = Box::new(PdfProcessorImpl::default());
        let embedder = PdfContentStreamLsb::new(processor);

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: vec![].into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![1, 2, 3]);

        let result = embedder.embed(cover, &payload);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));
    }

    #[test]
    fn test_lsb_image_roundtrip_256x256() {
        let embedder = LsbImage::new();

        // Create 256x256 white RGBA image
        let width = 256_u32;
        let height = 256_u32;
        let pixel_count = width * height;
        let data = vec![255u8; (pixel_count * 4) as usize]; // RGBA

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        // 64-byte payload
        let payload = Payload::from_bytes(vec![0xAB; 64]);

        // Embed
        let stego = embedder.embed(cover.clone(), &payload).expect("embed");

        // Verify pixel changes are ±1
        let orig_pixels = cover.data.as_ref();
        let stego_pixels = stego.data.as_ref();
        for (i, (orig, stego_val)) in orig_pixels.iter().zip(stego_pixels.iter()).enumerate() {
            let diff = orig.abs_diff(*stego_val);
            assert!(
                diff <= 1,
                "pixel at index {i} changed by more than 1: {orig} -> {stego_val}"
            );
        }

        // Extract
        let extracted = embedder.extract(&stego).expect("extract");
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn test_lsb_image_capacity_10x10() {
        let embedder = LsbImage::new();

        let width = 10_u32;
        let height = 10_u32;
        let pixel_count = width * height;
        let data = vec![0u8; (pixel_count * 4) as usize];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        let cap = embedder.capacity(&cover).expect("capacity");

        // 10x10 = 100 pixels
        // 100 * 3 = 300 bits
        // 300 - 32 (header) = 268 bits
        // 268 / 8 = 33 bytes
        assert_eq!(cap.bytes, 33);
        assert_eq!(cap.technique, StegoTechnique::LsbImage);
    }

    #[test]
    fn test_lsb_image_insufficient_capacity() {
        let embedder = LsbImage::new();

        let width = 10_u32;
        let height = 10_u32;
        let pixel_count = width * height;
        let data = vec![0u8; (pixel_count * 4) as usize];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: data.into(),
            metadata,
        };

        // Try to embed 100 bytes (capacity is only 33)
        let payload = Payload::from_bytes(vec![0xAB; 100]);

        let result = embedder.embed(cover, &payload);
        assert!(matches!(
            result,
            Err(StegoError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn test_lsb_image_bmp_support() {
        let embedder = LsbImage::new();

        let width = 100_u32;
        let height = 100_u32;
        let pixel_count = width * height;
        let data = vec![128u8; (pixel_count * 4) as usize];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());

        let cover = CoverMedia {
            kind: CoverMediaKind::BmpImage,
            data: data.into(),
            metadata,
        };

        let payload = Payload::from_bytes(vec![1, 2, 3, 4, 5]);

        // Embed
        let stego = embedder.embed(cover, &payload).expect("embed");

        // Extract
        let extracted = embedder.extract(&stego).expect("extract");
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn test_dct_jpeg_stub_returns_not_implemented() {
        let embedder = DctJpeg::new();

        let cover = CoverMedia {
            kind: CoverMediaKind::JpegImage,
            data: vec![].into(),
            metadata: std::collections::HashMap::new(),
        };

        let payload = Payload::from_bytes(vec![1, 2, 3]);

        // Should return UnsupportedCoverType error indicating not implemented
        let result = embedder.embed(cover.clone(), &payload);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.extract(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));

        let result = embedder.capacity(&cover);
        assert!(matches!(result, Err(StegoError::UnsupportedCoverType { .. })));
    }
}
