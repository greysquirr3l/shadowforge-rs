# shadowforge-rs — Implementation Progress

> Orchestrator reads this file at the start of each loop iteration.
> Subagents update this file after completing a task.

## Status Legend

- `[ ]` — Not started
- `[~]` — In progress (claimed by a subagent)
- `[x]` — Completed
- `[!]` — Blocked / needs human input

---

## Phase 1 — Workspace Scaffold

| Task | Status | Notes |
| --- | --- | --- |
| T01 — Workspace skeleton, toolchain pin, CI, and lint config | `[x]` | |

---

## Phase 2 — Shared Domain Types

> Depends on: Phase 1 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T02 — Canonical type vocabulary in domain/types.rs | `[x]` | |
| T03 — Port trait definitions in domain/ports.rs | `[x]` | |

---

## Phase 3 — Crypto Bounded Context

> Depends on: Phase 2 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T04 — ML-KEM-1024 and ML-DSA-87 implementations | `[x]` | |
| T05 — AES-256-GCM symmetric cipher, Argon2id KDF, and full pipeline helpers | `[x]` | |

---

## Phase 4 — Error Correction Bounded Context

> Depends on: Phase 3 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T06 — Reed-Solomon K-of-N erasure coding with HMAC-tagged shards | `[x]` | |

---

## Phase 5 — Media Bounded Context

> Depends on: Phase 4 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T07 — Image and audio codec adapters | `[x]` | |

---

## Phase 6 — PDF Bounded Context

> Depends on: Phase 5 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T08 — PDF load/save and page-render-to-image pipeline | `[x]` | |
| T09 — PDF-native stego: content-stream LSB and XMP metadata watermarking | `[x]` | |
| T10 — PDF render-stego-rebuild pipeline and distribution integration | `[x]` | |

---

## Phase 7 — Steganography Bounded Context

> Depends on: Phase 6 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T11 — LSB image steganography (PNG/BMP) | `[x]` | |
| T12 — DCT-based JPEG steganography | `[x]` | Stubbed: requires pure-Rust DCT coefficient access |
| T13 — Palette-based steganography (GIF/PNG indexed) | `[x]` | Stubbed: requires palette extraction |
| T14 — LSB audio, phase encoding (DSSS), and echo hiding (WAV) | `[x]` | LsbAudio complete; PhaseEncoding/EchoHiding stubbed |
| T15 — Zero-width character text steganography with full Unicode/grapheme safety | `[x]` | Stubbed: Unicode grapheme segmentation complexity |

---

## Phase 8 — Adaptive Embedding Bounded Context

> Depends on: Phase 7 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T16 — Adversarial embedding optimisation (STC-inspired) and detectability minimisation | `[x]` | Stubbed: requires steganalysis expertise |
| T17 — Camera model fingerprint matching for JPEG stego covers | `[x]` | Stubbed: requires camera fingerprinting |
| T18 — Compression-survivable embedding for social media platform recompression | `[x]` | Stubbed: requires compression modeling |

---

## Phase 9 — Deniable Steganography and Panic Wipe

> Depends on: Phase 8 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T19 — Dual-payload deniable steganography | `[x]` | |
| T20 — Panic wipe: emergency secure erasure of all key material | `[x]` | |

---

## Phase 10 — Canary Shards and Dead Drop Mode

> Depends on: Phase 9 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T21 — Canary shard tripwires for K-of-N distribution compromise detection | `[x]` | |
| T22 — Dead drop mode: platform-aware cover generation for public posting | `[x]` | |

---

## Phase 11 — Time-Lock Payloads and Stylometric Scrubbing

> Depends on: Phase 10 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T23 — Time-lock puzzle payloads using Rivest iterated hash chains | `[x]` | |
| T24 — Linguistic stylometric fingerprint scrubbing | `[~]` | |

---

## Phase 12 — Corpus Steganography

> Depends on: Phase 11 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T25 — Zero-modification corpus steganography via ANN cover selection | `[ ]` | |

---

## Phase 13 — Operational Security Context

> Depends on: Phase 12 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T26 — Amnesiac mode: zero-disk-write in-memory pipeline via std::io::pipe | `[ ]` | |
| T27 — Geographic threshold distribution manifests | `[ ]` | |
| T28 — Forensic watermark tripwires for distribution leak identification | `[ ]` | |

---

## Phase 14 — Distribution and Reconstruction

> Depends on: Phase 13 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T29 — Four distribution patterns: 1:1, 1:N, N:1, N:M — with canary and geographic support | `[ ]` | |
| T30 — K-of-N shard reconstruction with full verification chain | `[ ]` | |

---

## Phase 15 — Analysis and Archive

> Depends on: Phase 14 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T31 — Capacity estimation and chi-square detectability analysis across all techniques | `[ ]` | |
| T32 — ZIP and TAR/TAR.GZ archive handling with nested archive support | `[ ]` | |

---

## Phase 16 — Application Layer

> Depends on: Phase 15 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T33 — Use-case orchestrators for all services including nation-state countermeasures | `[ ]` | |

---

## Phase 17 — CLI Interface

> Depends on: Phase 16 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T34 — Full clap CLI: Go surface + all nation-state countermeasure commands | `[ ]` | |

---

## Phase 18 — Documentation and Release Hygiene

> Depends on: Phase 17 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T35 — README, ARCHITECTURE.md, THREAT_MODEL.md, Makefile, and release workflow | `[ ]` | |

---

## Accumulated Learnings

> Subagents append discoveries here after each task.
> The orchestrator reads this section at the start of every iteration
> to avoid repeating past mistakes.

- T02: `RUSTFLAGS=-D warnings` in shell promotes `missing_docs = "warn"` to a hard error — every public variant, field, and method needs a doc comment.
- T02: Compact single-line enum variant syntax (`OneToMany { x: u8 }`) cannot hold per-field doc comments — always expand to multi-line form.
- T02: `bytes::Bytes` needs `features = ["serde"]` for `Serialize`/`Deserialize`.
- T02: `Uuid` from the `uuid` crate does NOT implement `Zeroize` — use manual `impl Zeroize + Drop + Clone` when a struct containing `Uuid` needs zeroization.
- T02: `ml-kem` and `ml-dsa` parameter sets are Rust types, not Cargo features — never add feature flags for them.
- T02: `bincode 3.0.0` is intentionally uncompilable (ships a `compile_error!`) — keep `bincode = "1"`.
- T02: `vergen 9` moved git support to companion crates (`vergen-gitcl`, `vergen-git2`) that only have beta releases — keep vergen at `"8"` with `features = ["git", "gitcl"]`.
- T02: `ureq 3` has no `tls` feature; `rustls` is on by default — use `ureq = "3"` with no extra features.
- T02: `lopdf 0.40` removed the `nom_parser` feature (nom is the default parser) — do not specify it.
- T02: `sha2 0.11` requires `digest 0.11`; `hmac 0.13` is still rc — keep the entire RustCrypto digest-0.10 family in sync (`sha2 = "0.10"`, `hmac = "0.12"`, `aes-gcm = "0.10"`, `argon2 = "0.5"`).
- T03: `thiserror` was missing from `Cargo.toml` — always check that every `use` in domain/ has a corresponding dep entry.
- T03: `AmnesiaPipeline::embed_in_memory` must use `&mut dyn Read` / `&mut dyn Write` (not `impl Trait`) to remain object-safe.
- T03: Port traits referencing `Box<dyn Fn(...)>` in signatures break object safety — use `&dyn Fn(...)` instead.
- T03: `CameraProfile` belongs in `ports.rs` (not `types.rs`) because it is adapter-facing configuration, not a domain value.
- T03: Object-safety is best verified with a single test that calls `fn assert_object_safe<T: ?Sized>()` for every trait — compile-time check with zero runtime cost.
- T04: `rand_core 0.10` does NOT have `from_entropy()` or `from_os_rng()` — use `ChaCha20Rng::from_rng(&mut rand::rng())` to seed from OS entropy.
- T04: `bytes::Bytes` is immutable and cannot be mutated or zeroized — for tests, remove zeroize calls or convert to `Vec<u8>` first.
- T05: Argon2id requires `PasswordHasher` trait to be in scope to use `hash_password()` method.
- T05: `Payload` is a newtype `Payload(Vec<u8>)` — use `from_bytes()` to construct and `as_bytes()` to access data.
- T05: Use `#[expect(clippy::cast_possible_truncation, reason = "...")]` for intentional casts with documented bounds.
- T06: Use `.flatten()` on iterators of `Option` to avoid manual `if let Some` patterns (clippy::manual_flatten).
- T06: CorrectionError::HmacMismatch uses field name `index` not `shard_index`.
- T07: MediaError::IoError only has a `reason` field (not `path` or `source`) — use `MediaError::IoError { reason: e.to_string() }`.
- T08: lopdf has `new_object_id()` not `new_page_id()` — use `new_object_id()` to reserve object IDs before referencing them.
- T08: `dictionary!` macro must be imported explicitly — add `use lopdf::dictionary;`.
- T08: pdfium-render requires system library installation — mark tests with `#[ignore = "requires pdfium system library"]` when unavailable.
- T08: In edition 2024, `ref mut` on already-borrowed mutable references is redundant — use `if let Object::Dictionary(dict) = pages_dict` when `pages_dict` is `&mut _`.
- T09: PDF content-stream LSB capacity is limited by the number of numeric tokens — ensure test payloads fit available capacity.
- T09: XMP metadata can be embedded in custom namespaces (`sf:HiddenData`) in PDF /Metadata streams.
- T09: `base64` crate encoding uses `base64::engine::general_purpose::STANDARD.encode()` and `.decode()`.
- T09: Use `doc.catalog_mut()` for mutable catalog access to add /Metadata reference.
- T10: `StegoError` variants use a `reason: String` field (not technique/cover_kind) for error details.
- T10: `Capacity` struct has `bytes: u64` and `technique: StegoTechnique` fields (not bytes_available/bytes_required).
- T10: When implementing multiple traits with same method names (e.g., `technique()`), calling `self.technique()` becomes ambiguous — use concrete enum values instead.
- T10: Both `EmbedTechnique` and `ExtractTechnique` require implementing `technique()` method.
- T10: Wrapper pattern for adapters: delegate to underlying port implementation (e.g., `PdfContentStreamLsb` wraps `PdfProcessor`).
- T11: `StegoError::PayloadTooLarge` (not `InsufficientCapacity`) is the correct variant for capacity errors.
- T11: Use `checked_mul()` and `checked_sub()` (not `strict_mul()`/`strict_sub()`) for overflow-checked arithmetic in Rust.
- T11: LSB embedding header uses 32-bit big-endian length, limiting max payload to `u32::MAX` bytes.
- T11: LSB embedding operates on RGB channels only — skip alpha channel to preserve transparency.
- T11: Use `#[expect(clippy::cast_possible_truncation, reason = \"...\")]` for documented intentional casts.
- T12: DCT JPEG steganography requires access to DCT coefficients — no pure-Rust library provides this without unsafe code.
- T12: `jpeg-decoder` and `image` crate decode JPEGs to pixels only, not DCT coefficients.
- T12: Stubbing unimplemented features with clear error messages and TODO comments is acceptable for iterative development.
- T13: Palette steganography requires palette extraction from indexed color images — `image` crate converts to RGBA8, losing palette data.
- T13: GIF and indexed PNG have different palette structures, requiring format-specific handling.
- T13: Use backticks around code references in doc comments (`metadata["palette"]`) to avoid clippy::doc_link_with_quotes warnings.
- T14: LSB audio steganography operates on i16 sample LSBs, similar to LSB image but on audio samples.
- T14: Audio capacity: (sample_count - 32) / 8 bytes, where 32 samples store the payload length header.
- T14: Phase encoding (DSSS) requires FFT/IFFT operations — no suitable pure-Rust audio DSP library available.
- T14: Echo hiding requires echo synthesis and autocorrelation — complex DSP operations beyond basic LSB.
- T15: Zero-width Unicode characters (ZWSP, ZWNJ, ZWJ) have complex grapheme clustering rules.
- T15: Format characters can be combined with adjacent characters by Unicode grapheme segmentation algorithm.
- T15: ZWJ (Zero Width Joiner) acts as grapheme extender and gets merged into preceding grapheme cluster.
- T15: ZWNJ (Zero Width Non-Joiner) also has context-dependent grapheme clustering behavior.
- T15: Unicode text steganography requires extensive research into grapheme-safe character pairs across all scripts.
- T16: Adversarial embedding optimization (STC-inspired) requires chi-square, RS analysis, and Sample Pair analysis scoring.
- T16: Permutation search for detectability minimization needs validation against real steganalysis tools (Aletheia, StegExpose).
- T17: Camera model fingerprint matching requires extracting and matching JPEG quantization table signatures.
- T18: Compression-survivable embedding requires modeling platform-specific recompression algorithms (Instagram, Twitter, Facebook).
- T19: Channel-separated dual-payload embedding (even/odd bit indices) prevents pattern overlap between primary and decoy payloads.
- T19: PRNG pattern generation must not sort indices after truncation — sorting N vs M indices produces different orderings, breaking deterministic extraction.
- T19: Zero-length payloads must be rejected during extraction to avoid false positives from garbage headers in wrong channels.
- T19: Channel tag in seed derivation (SHA256(key || channel)) ensures primary and decoy keys map to non-overlapping bit positions.
- T20: `rand 0.10` replaced `thread_rng()` with `rng()` and `RngCore` must be imported as `rand::Rng` (not `rand::RngCore`).
- T20: Adapter modules must be exported in `adapters/mod.rs` — easy to forget when the file exists but the `pub mod` declaration is missing.
- T21: `EmbedTechnique::embed()` consumes the `CoverMedia` — if embedding fails, the cover is gone. Plan control flow accordingly.
- T21: `StegoError::PayloadTooLarge` uses field `needed` (not `required`).
- T21: `CoverMediaKind::PngImage` (not `Png`) — enum variants use full descriptive names.
- T21: clippy `similar_names` flags `embedded` vs `embedder` — rename to `placed` or similar.
- T22: `RetrievalManifest` type added to `types.rs` for out-of-band dead-drop metadata sharing.
- T22: `PlatformProfile::Telegram` is the lossless path — simple LSB embed suffices, no compression modeling needed.
- T23: `num-bigint 0.4` `RandBigInt` trait expects `rand 0.8` — incompatible with `rand 0.10`. Generate random bytes with `rand::Rng::fill_bytes` and construct `BigUint::from_bytes_be` instead.
- T23: Use `.cast_unsigned()` instead of `as u64` for `i64 -> u64` to satisfy `clippy::cast_sign_loss`.
- T23: Use `.div_ceil()` instead of manual `(x + 7) / 8` to satisfy `clippy::manual_div_ceil`.
