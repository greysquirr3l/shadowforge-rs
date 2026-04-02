//! PDF processing adapter using lopdf and pdfium-render.

use std::collections::HashMap;
use std::io::BufWriter;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose;
use bytes::Bytes;
use image::{DynamicImage, ImageFormat};
use lopdf::{Document, Object, dictionary};
use pdfium_render::prelude::*;

use crate::domain::errors::PdfError;
use crate::domain::ports::PdfProcessor;
use crate::domain::types::{CoverMedia, CoverMediaKind, Payload};

// Metadata keys
const KEY_PAGE_COUNT: &str = "page_count";
const DEFAULT_DPI: u16 = 150;

/// PDF processor implementation using lopdf and pdfium-render.
///
/// Handles PDF loading/saving, page rasterisation, and PDF reconstruction.
#[derive(Debug)]
pub struct PdfProcessorImpl {
    /// DPI for page rasterisation.
    dpi: u16,
}

impl Default for PdfProcessorImpl {
    fn default() -> Self {
        Self { dpi: DEFAULT_DPI }
    }
}

impl PdfProcessorImpl {
    /// Create a new PDF processor with the given DPI.
    #[must_use]
    pub const fn new(dpi: u16) -> Self {
        Self { dpi }
    }
}

impl PdfProcessor for PdfProcessorImpl {
    fn load_pdf(&self, path: &Path) -> Result<CoverMedia, PdfError> {
        // Load PDF document
        let doc = Document::load(path).map_err(|e| PdfError::ParseFailed {
            reason: e.to_string(),
        })?;

        // Check if encrypted
        if doc.is_encrypted() {
            return Err(PdfError::Encrypted);
        }

        // Count pages
        let page_count = doc.get_pages().len();

        // Read raw bytes
        let bytes = std::fs::read(path).map_err(|e| PdfError::IoError {
            reason: e.to_string(),
        })?;

        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert(KEY_PAGE_COUNT.to_string(), page_count.to_string());

        Ok(CoverMedia {
            kind: CoverMediaKind::PdfDocument,
            data: Bytes::from(bytes),
            metadata,
        })
    }

    fn save_pdf(&self, media: &CoverMedia, path: &Path) -> Result<(), PdfError> {
        // Write raw PDF bytes to file
        std::fs::write(path, &media.data).map_err(|e| PdfError::IoError {
            reason: e.to_string(),
        })?;

        Ok(())
    }

    fn render_pages_to_images(&self, pdf: &CoverMedia) -> Result<Vec<CoverMedia>, PdfError> {
        // Initialize pdfium library
        let pdfium = Pdfium::new(
            Pdfium::bind_to_library(Pdfium::pdfium_platform_library_name_at_path("./"))
                .or_else(|_| Pdfium::bind_to_system_library())
                .map_err(|e| PdfError::RenderFailed {
                    page: 0,
                    reason: format!("Failed to load pdfium library: {e}"),
                })?,
        );

        // Load PDF from bytes
        let document = pdfium
            .load_pdf_from_byte_vec(pdf.data.to_vec(), None)
            .map_err(|e| PdfError::ParseFailed {
                reason: e.to_string(),
            })?;

        let page_count = document.pages().len();
        let mut images = Vec::with_capacity(page_count as usize);

        // Render each page
        for page_index in 0..page_count {
            let page = document
                .pages()
                .get(page_index)
                .map_err(|e| PdfError::RenderFailed {
                    page: page_index as usize,
                    reason: e.to_string(),
                })?;

            // Render to bitmap
            #[expect(
                clippy::cast_possible_truncation,
                reason = "DPI calculation for render"
            )]
            let target_width = (page.width().value * f32::from(self.dpi) / 72.0) as i32;

            let bitmap = page
                .render_with_config(&PdfRenderConfig::new().set_target_width(target_width))
                .map_err(|e| PdfError::RenderFailed {
                    page: page_index as usize,
                    reason: e.to_string(),
                })?;

            // Convert to RGBA8 image
            let width = bitmap.width().cast_unsigned();
            let height = bitmap.height().cast_unsigned();
            let rgba_data = bitmap.as_rgba_bytes();

            let img =
                image::RgbaImage::from_raw(width, height, rgba_data.clone()).ok_or_else(|| {
                    PdfError::RenderFailed {
                        page: page_index as usize,
                        reason: "invalid bitmap dimensions".to_string(),
                    }
                })?;

            // Build metadata
            let mut metadata = HashMap::new();
            metadata.insert("width".to_string(), width.to_string());
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("format".to_string(), "Png".to_string());
            metadata.insert("page_index".to_string(), page_index.to_string());

            images.push(CoverMedia {
                kind: CoverMediaKind::PngImage,
                data: Bytes::from(img.into_raw()),
                metadata,
            });
        }

        Ok(images)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "PDF reconstruction logic is inherently complex"
    )]
    fn rebuild_pdf_from_images(
        &self,
        images: Vec<CoverMedia>,
        _original: &CoverMedia,
    ) -> Result<CoverMedia, PdfError> {
        // Create a new PDF document
        let mut doc = Document::with_version("1.7");

        // Add each image as a page
        for (page_index, img_media) in images.iter().enumerate() {
            // Parse dimensions from metadata
            let width: u32 = img_media
                .metadata
                .get("width")
                .ok_or_else(|| PdfError::RebuildFailed {
                    reason: "missing width metadata".to_string(),
                })?
                .parse()
                .map_err(|e: std::num::ParseIntError| PdfError::RebuildFailed {
                    reason: e.to_string(),
                })?;

            let height: u32 = img_media
                .metadata
                .get("height")
                .ok_or_else(|| PdfError::RebuildFailed {
                    reason: "missing height metadata".to_string(),
                })?
                .parse()
                .map_err(|e: std::num::ParseIntError| PdfError::RebuildFailed {
                    reason: e.to_string(),
                })?;

            // Convert RGBA data to PNG bytes
            let img = image::RgbaImage::from_raw(width, height, img_media.data.to_vec())
                .ok_or_else(|| PdfError::RebuildFailed {
                    reason: "invalid image dimensions or data length".to_string(),
                })?;

            let dynamic_img = DynamicImage::ImageRgba8(img);
            let mut png_bytes = Vec::new();
            dynamic_img
                .write_to(&mut std::io::Cursor::new(&mut png_bytes), ImageFormat::Png)
                .map_err(|e| PdfError::RebuildFailed {
                    reason: e.to_string(),
                })?;

            // Create a page with the image dimensions (convert pixels to points: 72 DPI)
            #[expect(clippy::cast_precision_loss, reason = "image dimensions to PDF points")]
            let page_width = width as f32 * 72.0 / f32::from(self.dpi);
            #[expect(clippy::cast_precision_loss, reason = "image dimensions to PDF points")]
            let page_height = height as f32 * 72.0 / f32::from(self.dpi);

            let page_id = doc.new_object_id();
            let page = doc.add_object(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), page_width.into(), page_height.into()],
                "Contents" => Object::Reference((page_id.0 + 1, 0)),
                "Resources" => lopdf::dictionary! {
                    "XObject" => lopdf::dictionary! {
                        "Image1" => Object::Reference((page_id.0 + 2, 0)),
                    },
                },
            });

            // Create content stream that displays the image
            let content = format!("q\n{page_width} 0 0 {page_height} 0 0 cm\n/Image1 Do\nQ");
            let content_id = doc.add_object(lopdf::Stream::new(
                lopdf::dictionary! {},
                content.into_bytes(),
            ));

            // Add the PNG image as an XObject
            let image_id = doc.add_object(lopdf::Stream::new(
                lopdf::dictionary! {
                    "Type" => "XObject",
                    "Subtype" => "Image",
                    "Width" => i64::from(width),
                    "Height" => i64::from(height),
                    "ColorSpace" => "DeviceRGB",
                    "BitsPerComponent" => 8,
                    "Filter" => "FlateDecode",
                },
                png_bytes,
            ));

            // Verify object IDs match what we referenced
            assert_eq!(page, (page_id.0, 0));
            assert_eq!(content_id, (page_id.0 + 1, 0));
            assert_eq!(image_id, (page_id.0 + 2, 0));

            // Add page to pages collection
            if doc.catalog().is_err() {
                // Create catalog and pages root
                let pages_obj_id = doc.new_object_id();
                let catalog_id = doc.add_object(lopdf::dictionary! {
                    "Type" => "Catalog",
                    "Pages" => Object::Reference(pages_obj_id),
                });
                doc.trailer.set("Root", Object::Reference(catalog_id));

                doc.objects.insert(
                    pages_obj_id,
                    lopdf::Object::Dictionary(lopdf::dictionary! {
                        "Type" => "Pages",
                        "Kids" => vec![Object::Reference(page)],
                        "Count" => 1,
                    }),
                );
            } else {
                // Add to existing pages
                if let Ok(pages_ref) = doc.catalog().and_then(|c| c.get(b"Pages"))
                    && let Ok(pages_obj_id) = pages_ref.as_reference()
                    && let Ok(pages_dict) = doc.get_object_mut(pages_obj_id)
                    && let Object::Dictionary(dict) = pages_dict
                {
                    // Get current kids array
                    let mut kids = if let Ok(Object::Array(arr)) = dict.get(b"Kids") {
                        arr.clone()
                    } else {
                        vec![]
                    };
                    kids.push(Object::Reference(page));

                    dict.set("Kids", Object::Array(kids));
                    #[expect(clippy::cast_possible_wrap, reason = "page count fits in i64")]
                    dict.set("Count", (page_index + 1) as i64);
                }
            }
        }

        // Serialize to bytes
        let mut pdf_bytes = Vec::new();
        doc.save_to(&mut BufWriter::new(&mut pdf_bytes))
            .map_err(|e| PdfError::RebuildFailed {
                reason: e.to_string(),
            })?;

        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert(KEY_PAGE_COUNT.to_string(), images.len().to_string());

        Ok(CoverMedia {
            kind: CoverMediaKind::PdfDocument,
            data: Bytes::from(pdf_bytes),
            metadata,
        })
    }

    fn embed_in_content_stream(
        &self,
        pdf: CoverMedia,
        payload: &Payload,
    ) -> Result<CoverMedia, PdfError> {
        // Load PDF from bytes
        let mut doc = Document::load_from(&pdf.data[..]).map_err(|e| PdfError::ParseFailed {
            reason: e.to_string(),
        })?;

        // Convert payload to bits
        let payload_bits: Vec<u8> = payload
            .as_bytes()
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1))
            .collect();

        let mut bit_index = 0;

        // Iterate through all objects to find content streams
        let object_ids: Vec<_> = doc.objects.keys().copied().collect();
        for obj_id in object_ids {
            if bit_index >= payload_bits.len() {
                break;
            }

            if let Ok(obj) = doc.get_object_mut(obj_id)
                && let Object::Stream(stream) = obj
            {
                // Parse content stream
                let content = String::from_utf8_lossy(&stream.content);
                let mut modified_content = String::new();
                let mut tokens: Vec<&str> = content.split_whitespace().collect();

                for token in &mut tokens {
                    if bit_index >= payload_bits.len() {
                        modified_content.push_str(token);
                        modified_content.push(' ');
                        continue;
                    }

                    // Check if token is a number
                    if let Ok(mut num) = token.parse::<i32>() {
                        // Embed bit in LSB — bit_index < payload_bits.len() guaranteed by guard above
                        if let Some(&bit) = payload_bits.get(bit_index) {
                            if bit == 1 {
                                num |= 1; // Set LSB
                            } else {
                                num &= !1; // Clear LSB
                            }
                        }
                        modified_content.push_str(&num.to_string());
                        bit_index += 1;
                    } else {
                        modified_content.push_str(token);
                    }
                    modified_content.push(' ');
                }

                // Update stream content
                stream.set_content(modified_content.trim().as_bytes().to_vec());
            }
        }

        if bit_index < payload_bits.len() {
            return Err(PdfError::EmbedFailed {
                reason: format!(
                    "insufficient capacity: embedded {bit_index}/{} bits",
                    payload_bits.len()
                ),
            });
        }

        // Serialize modified PDF
        let mut pdf_bytes = Vec::new();
        doc.save_to(&mut pdf_bytes)
            .map_err(|e| PdfError::EmbedFailed {
                reason: e.to_string(),
            })?;

        Ok(CoverMedia {
            kind: pdf.kind,
            data: Bytes::from(pdf_bytes),
            metadata: pdf.metadata,
        })
    }

    fn extract_from_content_stream(&self, pdf: &CoverMedia) -> Result<Payload, PdfError> {
        // Load PDF from bytes
        let doc = Document::load_from(&pdf.data[..]).map_err(|e| PdfError::ParseFailed {
            reason: e.to_string(),
        })?;

        let mut extracted_bits = Vec::new();

        // Iterate through all objects to find content streams
        for obj in doc.objects.values() {
            if let Object::Stream(stream) = obj {
                // Parse content stream
                let content = String::from_utf8_lossy(&stream.content);
                let tokens: Vec<&str> = content.split_whitespace().collect();

                for token in tokens {
                    // Check if token is a number
                    if let Ok(num) = token.parse::<i32>() {
                        // Extract LSB
                        #[expect(clippy::cast_sign_loss, reason = "LSB is always 0 or 1")]
                        extracted_bits.push((num & 1) as u8);
                    }
                }
            }
        }

        // Convert bits to bytes
        if extracted_bits.is_empty() {
            return Err(PdfError::ExtractFailed {
                reason: "no numeric values found in content streams".to_string(),
            });
        }

        let mut payload_bytes = Vec::new();
        for chunk in extracted_bits.chunks(8) {
            if chunk.len() == 8 {
                let mut byte = 0u8;
                for (i, bit) in chunk.iter().enumerate() {
                    byte |= bit << (7 - i);
                }
                payload_bytes.push(byte);
            }
        }

        Ok(Payload::from_bytes(payload_bytes))
    }

    fn embed_in_metadata(
        &self,
        pdf: CoverMedia,
        payload: &Payload,
    ) -> Result<CoverMedia, PdfError> {
        // Load PDF from bytes
        let mut doc = Document::load_from(&pdf.data[..]).map_err(|e| PdfError::ParseFailed {
            reason: e.to_string(),
        })?;

        // Base64-encode payload
        let encoded = general_purpose::STANDARD.encode(payload.as_bytes());

        // Create XMP metadata with custom field
        let xmp_content = format!(
            r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
      xmlns:sf="http://shadowforge.org/ns/1.0/">
      <sf:HiddenData>{encoded}</sf:HiddenData>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#
        );

        // Create metadata stream
        let metadata_id = doc.add_object(lopdf::Stream::new(
            lopdf::dictionary! {
                "Type" => "Metadata",
                "Subtype" => "XML",
            },
            xmp_content.into_bytes(),
        ));

        // Add metadata reference to catalog
        if let Ok(catalog) = doc.catalog_mut() {
            catalog.set("Metadata", Object::Reference(metadata_id));
        } else {
            return Err(PdfError::EmbedFailed {
                reason: "failed to access catalog".to_string(),
            });
        }

        // Serialize modified PDF
        let mut pdf_bytes = Vec::new();
        doc.save_to(&mut pdf_bytes)
            .map_err(|e| PdfError::EmbedFailed {
                reason: e.to_string(),
            })?;

        Ok(CoverMedia {
            kind: pdf.kind,
            data: Bytes::from(pdf_bytes),
            metadata: pdf.metadata,
        })
    }

    fn extract_from_metadata(&self, pdf: &CoverMedia) -> Result<Payload, PdfError> {
        // Load PDF from bytes
        let doc = Document::load_from(&pdf.data[..]).map_err(|e| PdfError::ParseFailed {
            reason: e.to_string(),
        })?;

        // Get catalog
        let catalog = doc.catalog().map_err(|e| PdfError::ExtractFailed {
            reason: format!("failed to access catalog: {e}"),
        })?;

        // Get metadata reference
        let metadata_ref = catalog
            .get(b"Metadata")
            .map_err(|_| PdfError::ExtractFailed {
                reason: "no metadata found in catalog".to_string(),
            })?
            .as_reference()
            .map_err(|_| PdfError::ExtractFailed {
                reason: "metadata is not a reference".to_string(),
            })?;

        // Get metadata stream
        let metadata_obj = doc
            .get_object(metadata_ref)
            .map_err(|e| PdfError::ExtractFailed {
                reason: format!("failed to get metadata object: {e}"),
            })?;

        let metadata_stream = metadata_obj
            .as_stream()
            .map_err(|_| PdfError::ExtractFailed {
                reason: "metadata is not a stream".to_string(),
            })?;

        // Parse XMP content
        let xmp_content = String::from_utf8_lossy(&metadata_stream.content);

        // Extract base64 data from <sf:HiddenData> tag
        let start_tag = "<sf:HiddenData>";
        let end_tag = "</sf:HiddenData>";

        let start_idx = xmp_content
            .find(start_tag)
            .ok_or_else(|| PdfError::ExtractFailed {
                reason: "no sf:HiddenData tag found".to_string(),
            })?
            .strict_add(start_tag.len());

        let end_idx = xmp_content
            .find(end_tag)
            .ok_or_else(|| PdfError::ExtractFailed {
                reason: "no closing sf:HiddenData tag found".to_string(),
            })?;

        let encoded_data = &xmp_content[start_idx..end_idx];

        // Decode base64
        let decoded = general_purpose::STANDARD
            .decode(encoded_data.trim())
            .map_err(|e| PdfError::ExtractFailed {
                reason: format!("base64 decode failed: {e}"),
            })?;

        Ok(Payload::from_bytes(decoded))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_load_minimal_pdf() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let dir = tempdir()?;
        let path = dir.path().join("minimal.pdf");

        // Create a minimal valid PDF with one page
        let mut doc = Document::with_version("1.7");
        let catalog_pages = doc.new_object_id();
        let first_page = doc.new_object_id();

        doc.objects.insert(
            first_page,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((first_page.0 + 1, 0)),
            }),
        );

        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {}, b"".to_vec()));

        doc.objects.insert(
            catalog_pages,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(first_page)],
                "Count" => 1,
            }),
        );

        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(catalog_pages),
        });

        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.save(&path)?;

        // Load it
        let media = processor.load_pdf(&path)?;
        assert_eq!(media.kind, CoverMediaKind::PdfDocument);
        assert_eq!(media.metadata.get(KEY_PAGE_COUNT), Some(&"1".to_string()));
        Ok(())
    }

    #[test]
    #[ignore = "requires pdfium system library"]
    fn test_render_pages_returns_correct_count() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let dir = tempdir()?;
        let path = dir.path().join("two_page.pdf");

        // Create a 2-page PDF
        let mut doc = Document::with_version("1.7");
        let catalog_pages = doc.new_object_id();

        let page1_id = doc.new_object_id();
        doc.objects.insert(
            page1_id,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((page1_id.0 + 1, 0)),
            }),
        );
        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {}, b"".to_vec()));

        let page2_id = doc.new_object_id();
        doc.objects.insert(
            page2_id,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((page2_id.0 + 1, 0)),
            }),
        );
        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {}, b"".to_vec()));

        doc.objects.insert(
            catalog_pages,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Pages",
                "Kids" => vec![
                    Object::Reference(page1_id),
                    Object::Reference(page2_id),
                ],
                "Count" => 2,
            }),
        );

        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(catalog_pages),
        });

        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.save(&path)?;

        // Load and render
        let media = processor.load_pdf(&path)?;
        let images = processor.render_pages_to_images(&media)?;
        assert_eq!(images.len(), 2);
        Ok(())
    }

    #[test]
    #[ignore = "requires pdfium system library"]
    fn test_rebuild_pdf_roundtrip() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let dir = tempdir()?;
        let path = dir.path().join("original.pdf");

        // Create a 2-page PDF
        let mut doc = Document::with_version("1.7");
        let catalog_pages = doc.new_object_id();

        let page1_id = doc.new_object_id();
        doc.objects.insert(
            page1_id,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((page1_id.0 + 1, 0)),
            }),
        );
        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {}, b"".to_vec()));

        let page2_id = doc.new_object_id();
        doc.objects.insert(
            page2_id,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((page2_id.0 + 1, 0)),
            }),
        );
        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {}, b"".to_vec()));

        doc.objects.insert(
            catalog_pages,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Pages",
                "Kids" => vec![
                    Object::Reference(page1_id),
                    Object::Reference(page2_id),
                ],
                "Count" => 2,
            }),
        );

        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(catalog_pages),
        });

        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.save(&path)?;

        // Load, render, rebuild, and reload
        let original = processor.load_pdf(&path)?;
        let images = processor.render_pages_to_images(&original)?;
        let rebuilt = processor.rebuild_pdf_from_images(images, &original)?;

        // Save and reload to verify
        let rebuilt_path = dir.path().join("rebuilt.pdf");
        processor.save_pdf(&rebuilt, &rebuilt_path)?;
        let reloaded = processor.load_pdf(&rebuilt_path)?;

        assert_eq!(
            reloaded.metadata.get(KEY_PAGE_COUNT),
            original.metadata.get(KEY_PAGE_COUNT)
        );
        Ok(())
    }

    #[test]
    #[ignore = "lopdf requires actual encrypted content, not just Encrypt trailer"]
    fn test_encrypted_pdf_error() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let dir = tempdir()?;
        let path = dir.path().join("encrypted.pdf");

        // Create an encrypted PDF
        let mut doc = Document::with_version("1.7");
        let catalog_pages = doc.new_object_id();
        let first_page = doc.new_object_id();

        doc.objects.insert(
            first_page,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((first_page.0 + 1, 0)),
            }),
        );

        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {}, b"".to_vec()));

        doc.objects.insert(
            catalog_pages,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(first_page)],
                "Count" => 1,
            }),
        );

        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(catalog_pages),
        });

        doc.trailer.set("Root", Object::Reference(catalog_id));

        // Add encryption dictionary
        doc.trailer
            .set("Encrypt", Object::Reference((doc.max_id + 1, 0)));
        doc.objects.insert(
            (doc.max_id + 1, 0),
            Object::Dictionary(lopdf::dictionary! {
                "Filter" => "Standard",
                "V" => 1,
                "R" => 2,
            }),
        );

        doc.save(&path)?;

        // Try to load it
        let result = processor.load_pdf(&path);
        assert!(matches!(result, Err(PdfError::Encrypted)));
        Ok(())
    }

    #[test]
    fn test_content_stream_lsb_roundtrip() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let dir = tempdir()?;
        let path = dir.path().join("test.pdf");

        // Create a test PDF with content stream
        let mut doc = Document::with_version("1.7");
        let catalog_pages = doc.new_object_id();
        let first_page = doc.new_object_id();

        doc.objects.insert(
            first_page,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((first_page.0 + 1, 0)),
            }),
        );

        // Content stream with many numeric values for capacity
        let content = b"BT\n/F1 12 Tf\n100 700 Td\n(Hello) Tj\n200 650 Td\n(World) Tj\n50 600 Td\n(Test) Tj\n150 550 Td\n(PDF) Tj\nET\n1 0 0 1 0 0 cm\n";
        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {}, content.to_vec()));

        doc.objects.insert(
            catalog_pages,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(first_page)],
                "Count" => 1,
            }),
        );

        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(catalog_pages),
        });

        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.save(&path)?;

        // Load and embed payload (very small to fit limited capacity)
        let original = processor.load_pdf(&path)?;
        let payload = Payload::from_bytes(vec![0xAB]); // 1 byte = 8 bits (need 8+ numbers)
        let stego = processor.embed_in_content_stream(original, &payload)?;

        // Verify PDF is still parseable
        let stego_path = dir.path().join("stego.pdf");
        processor.save_pdf(&stego, &stego_path)?;
        let reloaded = processor.load_pdf(&stego_path)?;

        // Extract and verify
        let extracted = processor.extract_from_content_stream(&reloaded)?;
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
        Ok(())
    }

    #[test]
    fn test_metadata_embed_roundtrip() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let dir = tempdir()?;
        let path = dir.path().join("test.pdf");

        // Create a minimal test PDF
        let mut doc = Document::with_version("1.7");
        let catalog_pages = doc.new_object_id();
        let first_page = doc.new_object_id();

        doc.objects.insert(
            first_page,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((first_page.0 + 1, 0)),
            }),
        );

        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {}, b"".to_vec()));

        doc.objects.insert(
            catalog_pages,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(first_page)],
                "Count" => 1,
            }),
        );

        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(catalog_pages),
        });

        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.save(&path)?;

        // Load and embed payload
        let original = processor.load_pdf(&path)?;
        let payload = Payload::from_bytes(vec![0u8; 128]); // 128-byte payload
        let stego = processor.embed_in_metadata(original, &payload)?;

        // Verify PDF is still parseable
        let stego_path = dir.path().join("stego.pdf");
        processor.save_pdf(&stego, &stego_path)?;
        let reloaded = processor.load_pdf(&stego_path)?;

        // Extract and verify
        let extracted = processor.extract_from_metadata(&reloaded)?;
        assert_eq!(extracted.as_bytes(), payload.as_bytes());
        Ok(())
    }
}
