//! PDF processing adapter using lopdf and pdfium-render.

use std::collections::HashMap;
use std::env;
use std::io::BufWriter;
use std::path::Path;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose;
use bytes::Bytes;
use lopdf::{Document, Object, dictionary};
use pdfium_render::prelude::*;

use crate::domain::analysis::{PDF_CONTENT_STREAM_CAPACITY_KEY, estimate_capacity};
use crate::domain::errors::{PdfError, StegoError};
use crate::domain::ports::{EmbedTechnique, ExtractTechnique, PdfProcessor};
use crate::domain::types::{Capacity, CoverMedia, CoverMediaKind, Payload, StegoTechnique};

// Metadata keys
const KEY_PAGE_COUNT: &str = "page_count";

/// Bytes reserved at the front of a content stream for the payload length.
///
/// A 32-bit big-endian length, matching the header the image and audio
/// LSB techniques use. Without it the reader cannot tell where the payload
/// ends and the document's own operands begin.
///
/// Each bit occupies one numeric operand, so the header costs 32 operands.
const CONTENT_STREAM_HEADER_BYTES: usize = 4;
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

    fn bind_pdfium() -> Result<Pdfium, PdfError> {
        let mut bind_errors = Vec::new();

        // 1. Try explicit env var override (highest priority)
        if let Some(pdfium_dir) = env::var_os("PDFIUM_DYNAMIC_LIB_PATH") {
            let library_path = Pdfium::pdfium_platform_library_name_at_path(&pdfium_dir);
            match Pdfium::bind_to_library(library_path) {
                Ok(bindings) => return Ok(Pdfium::new(bindings)),
                Err(error) => bind_errors.push(format!(
                    "PDFIUM_DYNAMIC_LIB_PATH={}: {error}",
                    Path::new(&pdfium_dir).display()
                )),
            }
        }

        // 2. Try system library (searched via the OS dynamic linker)
        match Pdfium::bind_to_system_library() {
            Ok(bindings) => return Ok(Pdfium::new(bindings)),
            Err(error) => {
                bind_errors.push(format!("system library: {error}"));
            }
        }

        // 3. Try local directory (e.g., ./)
        let local_library = Pdfium::pdfium_platform_library_name_at_path("./");
        match Pdfium::bind_to_library(local_library) {
            Ok(bindings) => return Ok(Pdfium::new(bindings)),
            Err(error) => bind_errors.push(format!("./: {error}")),
        }

        // 4. Fail with helpful error — use PdfError::BindFailed so it's not confused with a page render failure
        Err(PdfError::BindFailed {
            reason: format!(
                "Failed to load pdfium library. Binding attempts: {}. \
                 Download a prebuilt binary from https://github.com/bblanchon/pdfium-binaries/, \
                 set PDFIUM_DYNAMIC_LIB_PATH, or disable the 'pdf' feature with --no-default-features --features corpus,adaptive.",
                bind_errors.join("; ")
            ),
        })
    }
}

/// The process-wide pdfium instance.
///
/// pdfium keeps its bindings in a global `OnceCell`, so it can only be
/// bound once per process; a second bind attempt fails with
/// `PdfiumLibraryBindingsAlreadyInitialized`. Binding here, once, and
/// handing out a handle to the result means every later call gets a working
/// library instead of an error.
static PDFIUM: LazyLock<Result<Pdfium, String>> = LazyLock::new(|| {
    PdfProcessorImpl::bind_pdfium().map_err(|e| match e {
        PdfError::BindFailed { reason } => reason,
        other => other.to_string(),
    })
});

impl PdfProcessor for PdfProcessorImpl {
    fn load_pdf(&self, path: &Path) -> Result<CoverMedia, PdfError> {
        // Load PDF document
        let doc = Document::load(path).map_err(|e| PdfError::ParseFailed {
            reason: e.to_string(),
        })?;

        // Reject encrypted documents.
        //
        // `was_encrypted()` is the check that matters. lopdf decrypts a
        // document whose user password is empty as it loads, and then drops
        // the `/Encrypt` entry from the trailer — so `is_encrypted()` is
        // false by the time we look, even though the file on disk is
        // encrypted. Embedding into such a document and writing it back
        // would silently strip its protection, so both flags are consulted:
        // `is_encrypted()` covers a document that could not be decrypted at
        // all, `was_encrypted()` covers one that was.
        if doc.was_encrypted() || doc.is_encrypted() {
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

        // Record how much a content stream can actually carry. The file
        // size says nothing useful: only the numeric operands of the page
        // content streams hold bits, and they are a small fraction of the
        // document.
        let bits = total_content_stream_bits(&doc)
            .saturating_sub((CONTENT_STREAM_HEADER_BYTES * 8) as u64);
        metadata.insert(
            PDF_CONTENT_STREAM_CAPACITY_KEY.to_string(),
            (bits / 8).to_string(),
        );

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
        // Initialize pdfium library using the CI-provided path when available.
        let pdfium = PDFIUM.as_ref().map_err(|reason| PdfError::BindFailed {
            reason: reason.clone(),
        })?;

        // Load PDF from bytes
        let document = pdfium
            .load_pdf_from_byte_vec(pdf.data.to_vec(), None)
            .map_err(|e| PdfError::ParseFailed {
                reason: e.to_string(),
            })?;

        let page_count = document.pages().len();
        let mut images = Vec::with_capacity(usize::try_from(page_count).unwrap_or(0));

        // Render each page
        for page_index in 0..page_count {
            let page = document
                .pages()
                .get(page_index)
                .map_err(|e| PdfError::RenderFailed {
                    page: usize::try_from(page_index).unwrap_or(0),
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
                    page: usize::try_from(page_index).unwrap_or(0),
                    reason: e.to_string(),
                })?;

            // Convert to RGBA8 image
            let width = bitmap.width().cast_unsigned();
            let height = bitmap.height().cast_unsigned();
            let rgba_data = bitmap.as_rgba_bytes();

            let img =
                image::RgbaImage::from_raw(width, height, rgba_data.clone()).ok_or_else(|| {
                    PdfError::RenderFailed {
                        page: usize::try_from(page_index).unwrap_or(0),
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

            // A PDF image XObject carries raw pixel samples, not a whole
            // PNG file: the `Filter` entry describes how those samples are
            // encoded. Writing PNG bytes here would declare `FlateDecode`
            // over data that is not a zlib stream, so a renderer decodes
            // garbage and the page comes out blank.
            //
            // The payload is RGBA, four samples per pixel. The XObject
            // declares `DeviceRGB`, three samples per pixel, so the alpha
            // channel is dropped below.
            let expected_len = usize::try_from(width)
                .ok()
                .and_then(|w| {
                    usize::try_from(height)
                        .ok()
                        .and_then(|h| w.checked_mul(h))
                        .and_then(|px| px.checked_mul(4))
                })
                .ok_or_else(|| PdfError::RebuildFailed {
                    reason: "image dimensions overflow".to_string(),
                })?;
            if img_media.data.len() != expected_len {
                return Err(PdfError::RebuildFailed {
                    reason: format!(
                        "expected {expected_len} bytes of RGBA data for {width}x{height}, got {}",
                        img_media.data.len()
                    ),
                });
            }
            let rgba = image::RgbaImage::from_raw(width, height, img_media.data.to_vec())
                .ok_or_else(|| PdfError::RebuildFailed {
                    reason: "invalid image dimensions or data length".to_string(),
                })?;
            // Convert rather than reinterpret. `RgbImage::from_raw` accepts
            // a buffer *longer* than the image needs and reuses its leading
            // bytes as RGB, which shifts every channel and leaves trailing
            // bytes in the stream; a real conversion drops alpha per pixel.
            let rgb_samples = image::DynamicImage::ImageRgba8(rgba).into_rgb8().into_raw();

            // Page dimensions in PDF points (72 DPI), from the image size.
            #[expect(clippy::cast_precision_loss, reason = "image dimensions to PDF points")]
            let page_width = width as f32 * 72.0 / f32::from(self.dpi);
            #[expect(clippy::cast_precision_loss, reason = "image dimensions to PDF points")]
            let page_height = height as f32 * 72.0 / f32::from(self.dpi);

            // Create the content stream and the image XObject first, so
            // their real object IDs are known before the page dictionary
            // references them. lopdf allocates IDs on insertion, so an ID
            // cannot be predicted by arithmetic on a previously reserved
            // one — `new_object_id` and `add_object` each advance the
            // counter independently.
            let content = format!("q\n{page_width} 0 0 {page_height} 0 0 cm\n/Image1 Do\nQ");
            let content_id = doc.add_object(lopdf::Stream::new(
                lopdf::dictionary! {},
                content.into_bytes(),
            ));

            let mut image_stream = lopdf::Stream::new(
                lopdf::dictionary! {
                    "Type" => "XObject",
                    "Subtype" => "Image",
                    "Width" => i64::from(width),
                    "Height" => i64::from(height),
                    "ColorSpace" => "DeviceRGB",
                    "BitsPerComponent" => 8,
                },
                rgb_samples,
            );
            // `Stream::compress` sets `Filter` to `FlateDecode` itself, and
            // only when compression actually shrinks the data. Declaring the
            // filter by hand would suppress this and leave the samples
            // stored uncompressed under a filter the reader would try to
            // apply.
            image_stream
                .compress()
                .map_err(|e| PdfError::RebuildFailed {
                    reason: e.to_string(),
                })?;
            let image_id = doc.add_object(image_stream);

            // Create a page with the image dimensions (convert pixels to points: 72 DPI)
            let page = doc.add_object(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), page_width.into(), page_height.into()],
                "Contents" => Object::Reference(content_id),
                "Resources" => lopdf::dictionary! {
                    "XObject" => lopdf::dictionary! {
                        "Image1" => Object::Reference(image_id),
                    },
                },
            });

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

        // Frame the payload with its length, so the reader knows where the
        // payload ends and the document's own operands begin.
        let payload_len = u32::try_from(payload.len()).map_err(|_| PdfError::EmbedFailed {
            reason: "payload too large for a content stream".to_string(),
        })?;
        let mut framed = Vec::with_capacity(payload.len() + 4);
        framed.extend_from_slice(&payload_len.to_be_bytes());
        framed.extend_from_slice(payload.as_bytes());

        let payload_bits: Vec<u8> = framed
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1))
            .collect();

        let mut bit_index = 0;

        // Write into the page content streams only. Every other stream in
        // the document holds binary data — a compressed image, a font — and
        // a bit written into one of those changes the bytes the decoder
        // sees, which shows up as a corrupted page.
        for obj_id in page_content_stream_ids(&doc) {
            if bit_index >= payload_bits.len() {
                break;
            }

            if let Ok(obj) = doc.get_object_mut(obj_id)
                && let Object::Stream(stream) = obj
            {
                let content = String::from_utf8_lossy(&stream.content);
                let modified_content =
                    embed_bits_into_content(&content, &payload_bits, &mut bit_index);
                stream.set_content(modified_content.into_bytes());
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

        // Read the page content streams only — the same set the embedder
        // writes to, so the two halves agree on where the payload is.
        for obj_id in page_content_stream_ids(&doc) {
            let Ok(obj) = doc.get_object(obj_id) else {
                continue;
            };
            let Object::Stream(stream) = obj else {
                continue;
            };

            let content = String::from_utf8_lossy(&stream.content);
            for token in content.split_whitespace() {
                if let Ok(number) = token.parse::<i32>() {
                    // Extract LSB
                    #[expect(clippy::cast_sign_loss, reason = "LSB is always 0 or 1")]
                    extracted_bits.push((number & 1) as u8);
                }
            }
        }

        let header_bits = CONTENT_STREAM_HEADER_BYTES * 8;
        if extracted_bits.len() < header_bits {
            return Err(PdfError::ExtractFailed {
                reason: "content streams carry too few values to hold a payload".to_string(),
            });
        }

        // The length prefix says how much of the stream is payload; the bits
        // after it belong to the document's own operands.
        let header = bits_to_bytes(extracted_bits.get(..header_bits).unwrap_or_default());
        let Some(header) = header
            .get(..CONTENT_STREAM_HEADER_BYTES)
            .and_then(|bytes| bytes.try_into().ok())
        else {
            return Err(PdfError::ExtractFailed {
                reason: "content stream header is malformed".to_string(),
            });
        };
        let payload_len = u32::from_be_bytes(header);
        let payload_byte_count = usize::try_from(payload_len).unwrap_or(0);
        let payload_end = header_bits + payload_byte_count * 8;
        if extracted_bits.len() < payload_end {
            return Err(PdfError::ExtractFailed {
                reason: "content stream holds fewer bits than the payload length claims"
                    .to_string(),
            });
        }

        let payload_bytes = bits_to_bytes(
            extracted_bits
                .get(header_bits..payload_end)
                .unwrap_or_default(),
        );
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

/// Check that `cover` is a PDF document.
fn ensure_pdf_kind(cover: &CoverMedia, technique: StegoTechnique) -> Result<(), StegoError> {
    if cover.kind != CoverMediaKind::PdfDocument {
        return Err(StegoError::UnsupportedCoverType {
            reason: format!("{technique:?} requires a PDF cover"),
        });
    }
    Ok(())
}

fn ensure_pdf_cover(cover: &CoverMedia, technique: StegoTechnique) -> Result<Capacity, StegoError> {
    ensure_pdf_kind(cover, technique)?;

    Ok(Capacity {
        bytes: estimate_capacity(cover, technique),
        technique,
    })
}

/// The object IDs of the content streams referenced by the document's pages.
///
/// Only page content streams are used for embedding. A document's other
/// streams hold binary data — compressed images, fonts, ICC profiles — and
/// writing bits into those corrupts them, so the image on the page changes
/// visibly.
fn page_content_stream_ids(doc: &Document) -> Vec<(u32, u16)> {
    let mut ids = Vec::new();
    for page_id in doc.get_pages().values() {
        let Ok(page) = doc.get_object(*page_id) else {
            continue;
        };
        let Ok(dict) = page.as_dict() else {
            continue;
        };
        let Ok(contents) = dict.get(b"Contents") else {
            continue;
        };
        match contents {
            Object::Reference(reference) => ids.push(*reference),
            Object::Array(items) => {
                for item in items {
                    if let Object::Reference(reference) = item {
                        ids.push(*reference);
                    }
                }
            }
            _ => {}
        }
    }
    ids
}

/// The number of bits a content stream can carry.
///
/// One bit fits in each numeric token: the embedder stores it in the token's
/// least significant bit, which moves the operand by at most one.
fn content_stream_bits(stream: &lopdf::Stream) -> u64 {
    let content = String::from_utf8_lossy(&stream.content);
    content
        .split_whitespace()
        .filter(|token| token.parse::<i32>().is_ok())
        .count() as u64
}

/// The total number of embeddable bits across the document's page content
/// streams.
fn total_content_stream_bits(doc: &Document) -> u64 {
    page_content_stream_ids(doc)
        .iter()
        .filter_map(|id| doc.get_object(*id).ok())
        .filter_map(|object| match object {
            Object::Stream(stream) => Some(stream),
            _ => None,
        })
        .map(content_stream_bits)
        .sum()
}

/// The exact payload capacity of a PDF cover for content-stream embedding.
///
/// This counts the numeric tokens in the document's page content streams,
/// which is what the embedder can actually use. A capacity derived from the
/// size of the file would be wrong by orders of magnitude: a page's content
/// stream is a small fraction of the document, and only its numeric
/// operands carry bits.
///
/// # Errors
/// Returns [`PdfError::ParseFailed`] if the cover is not a readable PDF.
pub fn pdf_content_stream_capacity(cover: &CoverMedia) -> Result<Capacity, PdfError> {
    let doc = Document::load_from(&cover.data[..]).map_err(|e| PdfError::ParseFailed {
        reason: e.to_string(),
    })?;

    let bits =
        total_content_stream_bits(&doc).saturating_sub((CONTENT_STREAM_HEADER_BYTES * 8) as u64);
    Ok(Capacity {
        bytes: bits / 8,
        technique: StegoTechnique::PdfContentStream,
    })
}

/// Write `bits` into the least significant bits of a content stream's numeric
/// tokens, returning the rewritten content and the number of bits consumed.
///
/// Tokens are rewritten as numbers, so a token written as `007` or `+5`
/// comes back as `7` or `5`. The value of an operand moves by at most one,
/// and the operator that reads it is untouched.
fn embed_bits_into_content(content: &str, bits: &[u8], bit_index: &mut usize) -> String {
    let mut out = String::with_capacity(content.len());
    let mut first = true;
    for token in content.split_whitespace() {
        if !first {
            out.push(' ');
        }
        first = false;

        if *bit_index < bits.len()
            && let Ok(mut number) = token.parse::<i32>()
        {
            let bit = bits.get(*bit_index).copied().unwrap_or(0);
            if bit == 1 {
                number |= 1;
            } else {
                number &= !1;
            }
            *bit_index += 1;
            out.push_str(&number.to_string());
            continue;
        }

        out.push_str(token);
    }
    out
}

/// Pack a bit sequence into bytes, most significant bit first.
fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .filter(|chunk| chunk.len() == 8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0u8, |byte, (index, &bit)| byte | (bit << (7 - index)))
        })
        .collect()
}

fn map_pdf_error(error: PdfError) -> StegoError {
    match error {
        PdfError::Encrypted => StegoError::UnsupportedCoverType {
            reason: "encrypted PDF documents are not supported".to_string(),
        },
        PdfError::ExtractFailed { .. } => StegoError::NoPayloadFound,
        PdfError::RenderFailed { page, reason } => StegoError::MalformedCoverData {
            reason: format!("pdf render failed on page {page}: {reason}"),
        },
        PdfError::ParseFailed { reason }
        | PdfError::RebuildFailed { reason }
        | PdfError::EmbedFailed { reason }
        | PdfError::IoError { reason } => StegoError::MalformedCoverData {
            reason: format!("pdf processing failed: {reason}"),
        },
        PdfError::BindFailed { reason } => StegoError::UnsupportedCoverType {
            reason: format!("pdfium library is not available: {reason}"),
        },
    }
}

/// Stego adapter that embeds payloads in PDF content streams.
#[derive(Debug, Default)]
pub struct PdfContentStreamStego {
    processor: PdfProcessorImpl,
}

impl PdfContentStreamStego {
    /// Create a content-stream PDF stego adapter with default processor settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl EmbedTechnique for PdfContentStreamStego {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfContentStream
    }

    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
        ensure_pdf_kind(cover, <Self as EmbedTechnique>::technique(self))?;
        pdf_content_stream_capacity(cover).map_err(map_pdf_error)
    }

    fn embed(&self, cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
        ensure_pdf_kind(&cover, <Self as EmbedTechnique>::technique(self))?;
        self.processor
            .embed_in_content_stream(cover, payload)
            .map_err(map_pdf_error)
    }
}

impl ExtractTechnique for PdfContentStreamStego {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfContentStream
    }

    fn extract(&self, stego: &CoverMedia) -> Result<Payload, StegoError> {
        ensure_pdf_kind(stego, <Self as ExtractTechnique>::technique(self))?;
        self.processor
            .extract_from_content_stream(stego)
            .map_err(map_pdf_error)
    }
}

/// Stego adapter that embeds payloads in PDF metadata fields.
#[derive(Debug, Default)]
pub struct PdfMetadataStego {
    processor: PdfProcessorImpl,
}

impl PdfMetadataStego {
    /// Create a metadata PDF stego adapter with default processor settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl EmbedTechnique for PdfMetadataStego {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfMetadata
    }

    fn capacity(&self, cover: &CoverMedia) -> Result<Capacity, StegoError> {
        ensure_pdf_cover(cover, <Self as EmbedTechnique>::technique(self))
    }

    fn embed(&self, cover: CoverMedia, payload: &Payload) -> Result<CoverMedia, StegoError> {
        ensure_pdf_cover(&cover, <Self as EmbedTechnique>::technique(self))?;
        self.processor
            .embed_in_metadata(cover, payload)
            .map_err(map_pdf_error)
    }
}

impl ExtractTechnique for PdfMetadataStego {
    fn technique(&self) -> StegoTechnique {
        StegoTechnique::PdfMetadata
    }

    fn extract(&self, stego: &CoverMedia) -> Result<Payload, StegoError> {
        ensure_pdf_cover(stego, <Self as ExtractTechnique>::technique(self))?;
        self.processor
            .extract_from_metadata(stego)
            .map_err(map_pdf_error)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{EncryptionState, EncryptionVersion, StringFormat};
    use std::fmt::Write as _;
    use tempfile::tempdir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Whether a test that needs pdfium should run.
    ///
    /// Rasterisation needs the pdfium shared library; parsing and rebuilding
    /// do not. `Ok(true)` means run the test, `Ok(false)` means skip it, and
    /// `Err` means fail: the suite stays green on a machine without pdfium
    /// while still exercising the real path on one that has it.
    ///
    /// `SHADOWFORGE_REQUIRE_PDFIUM` turns a missing library into a failure
    /// instead of a skip, so CI — which installs pdfium — cannot go green
    /// without ever exercising the rasterisation path.
    fn pdfium_usable() -> Result<bool, String> {
        match PDFIUM.as_ref() {
            Ok(_) => Ok(true),
            Err(reason) => {
                if env::var_os("SHADOWFORGE_REQUIRE_PDFIUM").is_some() {
                    Err(format!("pdfium is required but failed to load: {reason}"))
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Build a `CoverMedia` holding raw RGBA pixels, as
    /// `render_pages_to_images` produces.
    ///
    /// The pattern varies per pixel and per channel. A solid colour cannot
    /// detect a channel shift: every pixel then carries the same bytes, so
    /// an image whose channels were scrambled still yields the right colour
    /// at many sample points.
    fn raster_cover(width: u32, height: u32) -> CoverMedia {
        let mut img = image::RgbaImage::new(width, height);
        for (x, y, pixel) in img.enumerate_pixels_mut() {
            // The pattern is taken modulo 256 so each value fits in a byte.
            let r = u8::try_from(x.wrapping_mul(4) % 256).unwrap_or(0);
            let g = u8::try_from(y.wrapping_mul(7) % 256).unwrap_or(0);
            let b =
                u8::try_from(x.wrapping_mul(3).wrapping_add(y.wrapping_mul(5)) % 256).unwrap_or(0);
            *pixel = image::Rgba([r, g, b, 255]);
        }
        CoverMedia {
            kind: CoverMediaKind::PngImage,
            data: Bytes::from(img.into_raw()),
            metadata: HashMap::from([
                ("width".to_string(), width.to_string()),
                ("height".to_string(), height.to_string()),
            ]),
        }
    }

    /// A rebuilt PDF must reference its content stream and image `XObject`
    /// correctly.
    ///
    /// Object IDs are allocated by lopdf, not by arithmetic on a previously
    /// reserved ID, so a page that guesses `page_id + 1` / `page_id + 2`
    /// points at the wrong objects: `Contents` ends up referring to the page
    /// dictionary itself and `Image1` to the content stream. The result is a
    /// structurally invalid PDF that renders as a blank or broken page.
    #[test]
    fn rebuilt_pdf_page_references_correct_objects() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let cover = raster_cover(64, 64);

        let rebuilt = processor.rebuild_pdf_from_images(
            vec![cover],
            &CoverMedia {
                kind: CoverMediaKind::PngImage,
                data: Bytes::new(),
                metadata: HashMap::new(),
            },
        )?;

        let doc = Document::load_mem(&rebuilt.data)?;
        let page = doc
            .get_pages()
            .values()
            .next()
            .copied()
            .ok_or("rebuilt PDF has no pages")?;

        // `Contents` must resolve to a stream, not to the page dictionary.
        let page_dict = doc.get_object(page)?.as_dict()?;
        let contents_id = page_dict.get(b"Contents")?.as_reference()?;
        assert!(
            doc.get_object(contents_id)?.as_stream().is_ok(),
            "page /Contents must reference a content stream"
        );

        // `Image1` must resolve to the image XObject, not to the content
        // stream.
        let image_id = page_dict
            .get(b"Resources")?
            .as_dict()?
            .get(b"XObject")?
            .as_dict()?
            .get(b"Image1")?
            .as_reference()?;
        let image = doc.get_object(image_id)?.as_stream()?;
        assert_eq!(
            image
                .dict
                .get(b"Subtype")
                .ok()
                .and_then(|o| o.as_name().ok()),
            Some(&b"Image"[..]),
            "/Image1 must reference the image XObject"
        );
        Ok(())
    }

    /// A rebuilt PDF must render back to the image it was built from.
    ///
    /// This is the end-to-end consequence of the page dictionary
    /// referencing the wrong objects: the page still "renders", but as a
    /// blank or broken image.
    #[test]
    fn rebuilt_pdf_renders_back_to_the_original_image() -> TestResult {
        if !pdfium_usable()? {
            eprintln!("skipping: pdfium shared library not available");
            return Ok(());
        }
        let processor = PdfProcessorImpl::default();
        let cover = raster_cover(64, 64);
        let source = image::RgbaImage::from_raw(64, 64, cover.data.to_vec())
            .ok_or("source image has unexpected dimensions")?;

        let rebuilt = processor.rebuild_pdf_from_images(
            vec![cover],
            &CoverMedia {
                kind: CoverMediaKind::PngImage,
                data: Bytes::new(),
                metadata: HashMap::new(),
            },
        )?;

        let rendered = processor.render_pages_to_images(&rebuilt)?;
        assert_eq!(rendered.len(), 1, "rebuilt PDF must have one page");
        let page = rendered.first().ok_or("rebuilt PDF must have one page")?;

        let img = image::RgbaImage::from_raw(64, 64, page.data.to_vec())
            .ok_or("rendered image has unexpected dimensions")?;
        for (x, y, pixel) in img.enumerate_pixels() {
            assert_eq!(
                pixel.0,
                source.get_pixel(x, y).0,
                "rebuilt PDF must render pixel ({x}, {y}) unchanged"
            );
        }
        Ok(())
    }

    /// Build a PDF whose page content stream holds `numbers` numeric
    /// operands, plus an image `XObject` holding binary data.
    fn pdf_with_content_and_image(numbers: usize) -> CoverMedia {
        use std::fmt::Write as _;

        let mut content = String::from("S\n");
        for i in 0..numbers {
            let _ = write!(content, "{i} {} m ", i * 2);
        }
        let image_data: Vec<u8> = (0..64u8).collect();

        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let leaf_id = doc.new_object_id();

        let content_id = doc.add_object(lopdf::Stream::new(
            lopdf::dictionary! {},
            content.into_bytes(),
        ));
        let image_id = doc.add_object(lopdf::Stream::new(
            lopdf::dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 8,
                "Height" => 8,
                "ColorSpace" => "DeviceGray",
                "BitsPerComponent" => 8,
                "Filter" => "FlateDecode",
            },
            image_data,
        ));

        doc.objects.insert(
            leaf_id,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference(content_id),
                "Resources" => lopdf::dictionary! {
                    "XObject" => lopdf::dictionary! {
                        "Im0" => Object::Reference(image_id),
                    },
                },
            }),
        );
        doc.objects.insert(
            pages_id,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(leaf_id)],
                "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(pages_id),
        });
        doc.trailer.set("Root", Object::Reference(catalog_id));

        let mut bytes = Vec::new();
        doc.save_to(&mut std::io::BufWriter::new(&mut bytes))
            .unwrap_or_default();

        CoverMedia {
            kind: CoverMediaKind::PdfDocument,
            data: Bytes::from(bytes),
            metadata: HashMap::new(),
        }
    }

    /// The extractor must return exactly the embedded payload.
    ///
    /// Without a length prefix the reader cannot tell where the payload
    /// ends, so it keeps reading the document's own operands and returns
    /// trailing garbage alongside the message.
    #[test]
    fn content_stream_round_trip_returns_exactly_the_payload() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let cover = pdf_with_content_and_image(80);

        let payload = Payload::from_bytes(b"HELLO".to_vec());
        let stego = processor.embed_in_content_stream(cover, &payload)?;
        let extracted = processor.extract_from_content_stream(&stego)?;

        assert_eq!(
            extracted.as_bytes(),
            b"HELLO",
            "extraction must return exactly the embedded payload"
        );
        Ok(())
    }

    /// Embedding must leave the document's binary streams alone.
    ///
    /// A bit written into a compressed image changes the bytes its decoder
    /// sees, which shows up as a corrupted page. Only the page's content
    /// stream is a legitimate carrier.
    #[test]
    fn content_stream_embedding_leaves_image_streams_untouched() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let cover = pdf_with_content_and_image(80);

        let before = Document::load_from(&cover.data[..])?;
        let image_before = image_stream_bytes(&before);

        let payload = Payload::from_bytes(b"HELLO".to_vec());
        let stego = processor.embed_in_content_stream(cover, &payload)?;

        let after = Document::load_from(&stego.data[..])?;
        assert_eq!(
            image_stream_bytes(&after),
            image_before,
            "the image XObject must be byte-identical after embedding"
        );
        Ok(())
    }

    /// The capacity the technique reports must match what it can embed.
    ///
    /// A capacity derived from the document's file size overstates the real
    /// figure by orders of magnitude, which sends users down a path that
    /// cannot work.
    #[test]
    fn content_stream_capacity_matches_what_can_be_embedded() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let cover = pdf_with_content_and_image(80);
        let stego = PdfContentStreamStego::new();

        let capacity = stego.capacity(&cover)?.bytes;
        assert!(
            capacity > 0,
            "a content stream with 160 operands must report capacity"
        );

        let capacity = usize::try_from(capacity).unwrap_or(0);

        // A payload of exactly the reported size fits.
        let payload = Payload::from_bytes(vec![0x41u8; capacity]);
        processor.embed_in_content_stream(cover.clone(), &payload)?;

        // One byte more does not.
        let too_big = Payload::from_bytes(vec![0x41u8; capacity + 1]);
        let error = processor.embed_in_content_stream(cover, &too_big);
        assert!(
            error.is_err(),
            "a payload larger than the reported capacity must be rejected"
        );
        Ok(())
    }

    /// The bytes of the document's image `XObject`, if it has one.
    fn image_stream_bytes(doc: &Document) -> Option<Vec<u8>> {
        doc.objects.values().find_map(|object| match object {
            Object::Stream(stream) => {
                let is_image = stream
                    .dict
                    .get(b"Subtype")
                    .ok()
                    .and_then(|value| value.as_name().ok())
                    .is_some_and(|name| name == b"Image");
                is_image.then(|| stream.content.clone())
            }
            _ => None,
        })
    }

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

    /// Rendering must work more than once in the same process.
    ///
    /// pdfium keeps its bindings in a global `OnceCell`, so it can only be
    /// bound once; a processor that binds on every call therefore succeeds
    /// the first time and fails every time after. Caching the bound library
    /// keeps repeated renders working.
    #[test]
    fn test_render_pages_twice_in_one_process() -> TestResult {
        if !pdfium_usable()? {
            eprintln!("skipping: pdfium shared library not available");
            return Ok(());
        }
        let processor = PdfProcessorImpl::default();
        let dir = tempdir()?;
        let path = dir.path().join("one_page.pdf");

        let mut doc = Document::with_version("1.7");
        let catalog_pages = doc.new_object_id();
        let page_id = doc.new_object_id();
        doc.objects.insert(
            page_id,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Page",
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Contents" => Object::Reference((page_id.0 + 1, 0)),
            }),
        );
        doc.add_object(lopdf::Stream::new(
            lopdf::dictionary! {},
            b"q 1 0 0 1 0 0 cm Q".to_vec(),
        ));
        doc.objects.insert(
            catalog_pages,
            Object::Dictionary(lopdf::dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_id)],
                "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(catalog_pages),
        });
        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.save(&path)?;

        let media = processor.load_pdf(&path)?;
        assert_eq!(processor.render_pages_to_images(&media)?.len(), 1);
        assert_eq!(
            processor.render_pages_to_images(&media)?.len(),
            1,
            "a second render in the same process must succeed"
        );
        Ok(())
    }

    #[test]
    fn test_render_pages_returns_correct_count() -> TestResult {
        if !pdfium_usable()? {
            eprintln!("skipping: pdfium shared library not available");
            return Ok(());
        }
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
    fn test_rebuild_pdf_roundtrip() -> TestResult {
        if !pdfium_usable()? {
            eprintln!("skipping: pdfium shared library not available");
            return Ok(());
        }
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

    /// An encrypted PDF must be rejected.
    ///
    /// The PDF is encrypted for real, with lopdf's own `Document::encrypt`,
    /// and with an empty user password — the usual shape for a document
    /// whose owner password restricts editing while anyone may view it.
    ///
    /// lopdf decrypts such a document as it loads and then *removes* the
    /// `/Encrypt` entry from the trailer, so `is_encrypted()` no longer
    /// reports it. `was_encrypted()` is the flag that survives, and it is
    /// what the processor must consult.
    #[test]
    fn test_encrypted_pdf_error() -> TestResult {
        let processor = PdfProcessorImpl::default();
        let dir = tempdir()?;
        let path = dir.path().join("encrypted.pdf");

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

        doc.add_object(lopdf::Stream::new(
            lopdf::dictionary! {},
            b"q 1 0 0 1 0 0 cm Q".to_vec(),
        ));

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
        // The file identifier is an input to the encryption key derivation.
        doc.trailer.set(
            "ID",
            Object::Array(vec![
                Object::String(vec![0u8; 16], StringFormat::Literal),
                Object::String(vec![0u8; 16], StringFormat::Literal),
            ]),
        );

        let state = EncryptionState::try_from(EncryptionVersion::V1 {
            document: &doc,
            owner_password: "owner",
            // Empty user password: viewable by anyone, as most
            // permission-restricted PDFs are.
            user_password: "",
            permissions: lopdf::Permissions::default(),
        })?;
        doc.encrypt(&state)?;
        doc.save(&path)?;

        let result = processor.load_pdf(&path);
        assert!(
            matches!(result, Err(PdfError::Encrypted)),
            "an encrypted PDF must be rejected, got {:?}",
            result.map(|_| "Ok")
        );
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

        // Content stream with many numeric values for capacity.
        //
        // Each bit occupies one numeric operand, so a payload framed with
        // its 32-bit length needs 40 operands for a single byte.
        let mut content = String::from(
            "BT\n/F1 12 Tf\n100 700 Td\n(Hello) Tj\n200 650 Td\n(World) Tj\n50 600 Td\n(Test) Tj\n150 550 Td\n(PDF) Tj\nET\n1 0 0 1 0 0 cm\n",
        );
        for i in 0..60 {
            let _ = write!(content, "{i} {} m ", i * 3);
        }
        let content = content.into_bytes();
        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {}, content));

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
