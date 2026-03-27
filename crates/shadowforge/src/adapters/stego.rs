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
}
