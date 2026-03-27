# AGENTS.md

## Project

shadowforge-rs — shadowforge-rs is a production-grade quantum-resistant steganography toolkit
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


## Setup commands

- Build: `cargo build --workspace`
- Test: `cargo test --workspace`
- Lint: `cargo clippy --workspace -- -D warnings`

## Architecture: Hexagonal

- Domain layer must have zero I/O dependencies
- All external interactions go through port traits
- Adapters implement port traits and live in `adapters/`
- New capabilities require a new port trait before an adapter
- Depend inward: adapters → ports ← domain

## Code style

- Language: rust
- Strategy: TDD — write a failing test before any implementation code


## Rules

- Rust edition 2024, stable toolchain 1.94.1 — pin rust-toolchain.toml.

- Cargo workspace mono-repo. All crates live under crates/. Root Cargo.toml declares members = ['crates/*']. Current in-scope crate: crates/shadowforge. Module tree inside it: src/domain/, src/adapters/, src/application/, src/interface/. Future crates (shadowforge-web, shadowforge-api) add as new crates/ members — no restructuring required.

- domain/ is pure: no I/O, no tokio, no file system, no network. Port traits live here.

- All error types use thiserror. No .unwrap() or .expect() outside #[cfg(test)] blocks.

- Use #[expect(lint)] instead of #[allow(lint)] everywhere — it warns if the suppressed lint stops firing.

- Use zeroize + ZeroizeOnDrop on every struct that touches key material or plaintext payloads.

- Use subtle::ConstantTimeEq for all cryptographic comparisons — never == on secrets.

- PQC: ml-kem for encapsulation/decapsulation, ml-dsa for signing/verification. No other PQC crates.

- Symmetric layer: AES-256-GCM via aes-gcm crate. KDF: argon2 (Argon2id variant).

- No secrets or key material in tracing output at any log level.

- Reed-Solomon: reed-solomon-erasure crate. Do not roll a custom RS implementation.

- Use Vec::extract_if (1.87) to filter None/invalid shards before passing to the RS decoder.

- All text operations use grapheme cluster boundaries via the unicode-segmentation crate.

- Never slice a &str by raw byte offset. Always use str::floor_char_boundary or str::ceil_char_boundary (stable 1.91).

- Capacity counting on text covers uses .graphemes(true).count(), never .len() or .chars().count() alone.

- char::len_utf8() for byte-length accounting when reconstructing cover text after embedding.

- Zero-width character injection occurs only at grapheme cluster boundaries — never inside a multi-scalar cluster (e.g. emoji ZWJ sequences).

- All capacity and shard-index arithmetic uses strict_add / strict_sub / strict_mul (stable 1.91) — explicit panic on overflow rather than silent wrapping.

- Use std::sync::LazyLock and std::cell::LazyCell (stable 1.80) — no lazy_static, no once_cell.

- Use <[T]>::array_windows (stable 1.94) for sliding-window operations in phase encoding and echo hiding.

- Use std::io::pipe() (stable 1.87) for the amnesiac mode pipeline.

- PDF is a first-class bounded context. lopdf for parsing/writing. pdfium-render for page rasterisation.

- Any FFI blocks (e.g. pdfium-render bindings) must use unsafe extern syntax (required in edition 2024).

- Image processing: image crate only (PNG/BMP/JPEG/GIF). Audio: hound (WAV only).

- CLI: clap derive API. Three primary subcommand groups: embed, extract, keygen — each with sub-subcommands. Mirror Go CLI surface exactly, then extend.

- Logging: tracing + tracing-subscriber. Structured JSON output. RUST_LOG respected.

- Every public function in domain/ and application/ must have at least one test.

- All tests that touch key material must call zeroize on temporaries before asserting.

- supply-chain hygiene: deny.toml with cargo-deny. No yanked crates.

## Testing instructions

- Run `cargo test --workspace` before committing
- Every new public function needs at least one test
- Fix all test failures before marking a task complete

## Commit conventions

- Use conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`
- Focus commit messages on user impact, not file counts or line numbers

---

_Generated by [wiggum](https://github.com/greysquirr3l/wiggum)._
