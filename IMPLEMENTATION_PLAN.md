# shadowforge-rs — Implementation Plan

## Overview

shadowforge-rs is a production-grade quantum-resistant steganography toolkit
for journalists, whistleblowers, and dissidents operating against nation-state
adversaries. It is a ground-up Rust reimplementation of shadowforge (Go).

Architecture: Collapsed Hexagonal / DDD-lite — a Cargo workspace mono-repo
with all crates under crates/. Current scope is a single main crate
(crates/shadowforge) with four top-level modules (domain/, adapters/,
application/, interface/) and bounded contexts inside domain/. The workspace
structure is intentional: future crates (shadowforge-web, shadowforge-api,
etc.) add as new members under crates/ without restructuring anything.

Key improvements over the Go version:
  - PDF is a first-class bounded context (embed/extract, native watermarking,
    render-to-PNG pipeline, cover-medium via content-stream LSB).
  - PQC uses ml-kem and ml-dsa (pure Rust NIST finalists) — no CGo, no CIRCL.
  - All bounded contexts share a single coherent type vocabulary in
    domain/types.rs — no duplicate types across contexts.
  - Error handling is total: thiserror throughout, zero panics in non-test code.
  - All text operations are grapheme-cluster-safe via unicode-segmentation.

Bounded Contexts (all under crates/shadowforge/src/domain/):
  crypto        — ML-KEM-1024, ML-DSA-87, Argon2id, AES-256-GCM, secure zeroing
  correction    — Reed-Solomon erasure coding, K-of-N splitting/recovery
  stego         — 7 classic techniques + 2 PDF-native + 1 corpus-selection
  media         — image (PNG/BMP/JPEG/GIF) and audio (WAV) codec adapters
  pdf           — FIRST CLASS: embed/extract, page-render pipeline,
                  content-stream LSB, metadata watermarking
  distribution  — 4 patterns: 1:1, 1:N, N:1, N:M matrix
  reconstruction — K-of-N shard reassembly with manifest verification
  archive       — ZIP / TAR / TAR.GZ multi-carrier bundles
  analysis      — capacity estimation, chi-square detectability scoring

Nation-State Countermeasure Bounded Contexts:
  adaptive      — Adversarial embedding optimisation (STC-inspired), cover
                  profile matching (camera model fingerprints), compression-
                  survivable embedding for social media platforms
  deniable      — Dual-payload deniable steganography, panic wipe
  canary        — Canary shard tripwires for distribution compromise detection
  deadrop       — Dead drop mode: platform-aware cover generation for
                  posting to public services (no direct file transfer)
  timelock      — Time-lock puzzle payloads (Rivest iterated hash chain)
  scrubber      — Linguistic stylometric fingerprint scrubbing
  corpus        — Corpus steganography: zero-modification cover selection
                  via ANN search over a local image corpus index
  opsec         — Amnesiac mode (zero disk writes), geographic threshold
                  distribution manifests, forensic watermark tripwires


**Architecture**: hexagonal
**Language**: rust

---

## Phases


### Phase 1 — Workspace Scaffold

1. **T01 — Workspace skeleton, toolchain pin, CI, and lint config**
   Bootstrap a compilable Cargo workspace with a crates/shadowforge main crate, the full module tree stubbed, CI passing, and all tooling wired including new bounded context modules.


### Phase 2 — Shared Domain Types

1. **T02 — Canonical type vocabulary in domain/types.rs**
   Define every shared value object and entity referenced by all bounded contexts. No I/O, no external crate I/O dependencies.
   _Depends on: scaffold_
2. **T03 — Port trait definitions in domain/ports.rs**
   Define all object-safe port traits for all bounded contexts including the new nation-state countermeasure contexts.
   _Depends on: domain-types_


### Phase 3 — Crypto Bounded Context

1. **T04 — ML-KEM-1024 and ML-DSA-87 implementations**
   Implement Encryptor and Signer port traits using ml-kem and ml-dsa. Keys are zeroized on drop. Constant-time throughout.
   _Depends on: port-traits_
2. **T05 — AES-256-GCM symmetric cipher, Argon2id KDF, and full pipeline helpers**
   Implement SymmetricCipher port trait and the full encrypt_payload / decrypt_payload pipeline helpers used by every bounded context.
   _Depends on: crypto-pqc_


### Phase 4 — Error Correction Bounded Context

1. **T06 — Reed-Solomon K-of-N erasure coding with HMAC-tagged shards**
   Implement ErrorCorrector port trait. Support configurable data/parity ratios, partial shard recovery, and HMAC integrity per shard.
   _Depends on: port-traits_


### Phase 5 — Media Bounded Context

1. **T07 — Image and audio codec adapters**
   Implement MediaLoader for PNG/BMP/JPEG/GIF (image crate) and WAV (hound). CoverMedia.data holds raw decoded pixels or samples — not file bytes.
   _Depends on: port-traits_


### Phase 6 — PDF Bounded Context

1. **T08 — PDF load/save and page-render-to-image pipeline**
   Implement PdfProcessor: load/save PDF documents with lopdf and render pages to PNG images.
   _Depends on: media-codecs_
2. **T09 — PDF-native stego: content-stream LSB and XMP metadata watermarking**
   Implement PDF-native EmbedTechnique + ExtractTechnique for content-stream LSB and metadata/XMP embedding.
   _Depends on: pdf-core_
3. **T10 — PDF render-stego-rebuild pipeline and distribution integration**
   Wire the render-pages→stego-per-page→rebuild pipeline and ensure PDF covers work in all four distribution patterns.
   _Depends on: pdf-stego_


### Phase 7 — Steganography Bounded Context

1. **T11 — LSB image steganography (PNG/BMP)**
   Implement EmbedTechnique + ExtractTechnique for LsbImage. Operate on raw RGBA8 pixels.
   _Depends on: media-codecs_
2. **T12 — DCT-based JPEG steganography**
   Implement EmbedTechnique + ExtractTechnique for DctJpeg by modifying non-zero AC DCT coefficients.
   _Depends on: media-codecs_
3. **T13 — Palette-based steganography (GIF/PNG indexed)**
   Implement EmbedTechnique + ExtractTechnique for Palette technique operating on palette colour bytes.
   _Depends on: media-codecs_
4. **T14 — LSB audio, phase encoding (DSSS), and echo hiding (WAV)**
   Implement all three audio steganography techniques. Use array_windows (1.94) for sliding-window operations.
   _Depends on: media-codecs_
5. **T15 — Zero-width character text steganography with full Unicode/grapheme safety**
   Implement EmbedTechnique + ExtractTechnique for ZeroWidthText. All text operations are grapheme-cluster-safe — zero panic risk on any valid Unicode input.
   _Depends on: port-traits_


### Phase 8 — Adaptive Embedding Bounded Context

1. **T16 — Adversarial embedding optimisation (STC-inspired) and detectability minimisation**
   Implement AdaptiveOptimiser: after any EmbedTechnique produces a stego cover, permute bit assignments to minimise statistical detectability against chi-square, RS analysis, and Sample Pair analysis.
   _Depends on: stego-lsb-image, stego-dct-jpeg, stego-audio, reed-solomon_
2. **T17 — Camera model fingerprint matching for JPEG stego covers**
   Implement CoverProfileMatcher: match the statistical fingerprint of a JPEG cover to a known camera model profile to defeat model-based steganalysis.
   _Depends on: adaptive-embedding_
3. **T18 — Compression-survivable embedding for social media platform recompression**
   Implement CompressionSimulator and extend EmbedTechnique to produce stego images that survive a target platform's recompression pipeline intact.
   _Depends on: cover-profile-matching_


### Phase 9 — Deniable Steganography and Panic Wipe

1. **T19 — Dual-payload deniable steganography**
   Implement DeniableEmbedder: embed two payloads in one cover, each decryptable by a different key. The cover is mathematically identical regardless of which key is presented.
   _Depends on: stego-lsb-image, crypto-symmetric_
2. **T20 — Panic wipe: emergency secure erasure of all key material**
   Implement PanicWiper: a synchronous, best-effort secure wipe of all key files, config, and temp data. Produces no output, no error to caller. Used under duress.
   _Depends on: port-traits_


### Phase 10 — Canary Shards and Dead Drop Mode

1. **T21 — Canary shard tripwires for K-of-N distribution compromise detection**
   Implement CanaryService: embed an (N+1)th canary shard in a honeypot location. Canary access is a tripwire indicating distribution compromise.
   _Depends on: reed-solomon, crypto-symmetric_
2. **T22 — Dead drop mode: platform-aware cover generation for public posting**
   Implement DeadDropEncoder: produce stego covers specifically optimised for posting to public platforms. No direct file transfer between parties — the sender posts publicly, the recipient retrieves by URL.
   _Depends on: compression-survivable, cover-profile-matching_


### Phase 11 — Time-Lock Payloads and Stylometric Scrubbing

1. **T23 — Time-lock puzzle payloads using Rivest iterated hash chains**
   Implement TimeLockService: a payload cannot be decrypted before a specified time, even under compulsion. Uses Rivest's sequential squaring time-lock puzzle.
   _Depends on: crypto-symmetric_
2. **T24 — Linguistic stylometric fingerprint scrubbing**
   Implement StyloScrubber: normalise a text payload to destroy authorship attribution fingerprints without changing meaning.
   _Depends on: port-traits_


### Phase 12 — Corpus Steganography

1. **T25 — Zero-modification corpus steganography via ANN cover selection**
   Implement CorpusIndex and CorpusEmbedder: search a local image corpus for a cover whose natural bit pattern already encodes (or nearly encodes) the payload — minimising or eliminating modifications.
   _Depends on: stego-lsb-image, adaptive-embedding_


### Phase 13 — Operational Security Context

1. **T26 — Amnesiac mode: zero-disk-write in-memory pipeline via std::io::pipe**
   Implement AmnesiaPipeline: the entire embed/extract pipeline reads from stdin and writes to stdout with no temp files, no logs, no crash dumps. Uses std::io::pipe() (stable 1.87).
   _Depends on: application-services_
2. **T27 — Geographic threshold distribution manifests**
   Extend distribution to annotate shards with jurisdictional metadata, producing a GeographicManifest that makes legal compulsion across jurisdictions impractical.
   _Depends on: canary-shards, port-traits_
3. **T28 — Forensic watermark tripwires for distribution leak identification**
   Implement ForensicWatermarker: embed unique imperceptible variants in multiple copies of the same cover, allowing identification of which recipient leaked a copy.
   _Depends on: stego-lsb-image_


### Phase 14 — Distribution and Reconstruction

1. **T29 — Four distribution patterns: 1:1, 1:N, N:1, N:M — with canary and geographic support**
   Implement Distributor port trait with all four patterns, RS error correction, parallel processing, PDF cover support, canary injection, and geographic manifest generation.
   _Depends on: reed-solomon, stego-lsb-image, pdf-pipeline, canary-shards, geographic-distribution_
2. **T30 — K-of-N shard reconstruction with full verification chain**
   Implement Reconstructor: verify manifest, verify per-shard HMAC, RS-decode, decrypt, verify DSA signature. Handles partial shard sets and progress callbacks.
   _Depends on: distribution_


### Phase 15 — Analysis and Archive

1. **T31 — Capacity estimation and chi-square detectability analysis across all techniques**
   Implement CapacityAnalyser for all 10 stego techniques including CorpusSelection and PDF-native techniques.
   _Depends on: stego-lsb-image, stego-audio, stego-zero-width, pdf-stego, corpus-stego, adaptive-embedding_
2. **T32 — ZIP and TAR/TAR.GZ archive handling with nested archive support**
   Implement ArchiveHandler for ZIP, TAR, TAR.GZ with automatic format detection and nested archive support.
   _Depends on: port-traits_


### Phase 16 — Application Layer

1. **T33 — Use-case orchestrators for all services including nation-state countermeasures**
   Wire all bounded contexts into thin application services. No file I/O. CryptoBundle passed by reference throughout.
   _Depends on: distribution, reconstruction, analysis, archive, pdf-pipeline, deniable-stego, panic-wipe, canary-shards, dead-drop, time-lock, stylo-scrubber, corpus-stego, forensic-watermark-tripwire_


### Phase 17 — CLI Interface

1. **T34 — Full clap CLI: Go surface + all nation-state countermeasure commands**
   Implement the complete CLI mirroring shadowforge Go CLI and extending with all new commands. This is the user-facing surface — operational security, clarity, and usability matter.
   _Depends on: application-services_


### Phase 18 — Documentation and Release Hygiene

1. **T35 — README, ARCHITECTURE.md, THREAT_MODEL.md, Makefile, and release workflow**
   Write comprehensive documentation including a threat model targeting nation-state adversaries, an architecture diagram, and a release workflow for all platforms.
   _Depends on: cli_


---

## Preflight Commands

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

---

_Generated by [wiggum](https://github.com/greysquirr3l/wiggum)._
