# T15 — Zero-width character text steganography with full Unicode/grapheme safety

> **Depends on**: T-port-traits.

## Goal

Implement EmbedTechnique + ExtractTechnique for ZeroWidthText. All text operations are grapheme-cluster-safe — zero panic risk on any valid Unicode input.

## Project Context

- Project: `shadowforge-rs` — shadowforge-rs is a production-grade quantum-resistant steganography toolkit
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

- Language: rust
- Architecture: hexagonal

### Architecture: Hexagonal (Ports & Adapters)

- **Domain layer** (`domain/`): Pure business logic, no I/O dependencies
- **Ports** (`ports/`): Trait boundaries that define capabilities the domain needs
- **Adapters** (`adapters/`): Implementations of ports (HTTP, DB, filesystem, etc.)
- Keep domain types free of framework-specific derives (no `#[sqlx::FromRow]` etc.)
- Depend inward: adapters → ports ← domain

## Strategy: TDD (Red-Green-Refactor)

### 1. RED — Write failing tests first

- Round-trip: 1000-character ASCII cover, 64-byte payload.
- Round-trip: Arabic cover text (multi-byte scalars), 32-byte payload — assert no panic and exact recovery.
- Round-trip: cover text containing 👨‍👩‍👧 (ZWJ emoji) — assert emoji is intact in output.
- Round-trip: Thai script cover — multi-byte grapheme clusters, exact recovery.
- strip_zero_width removes all ZWSP/ZWJ from embedded text.
- Overflow → Err.
- No payload present → Err(StegoError::NoPayloadFound).
- Raw byte slicing of &str must not appear anywhere in this module — clippy custom lint or comment audit.

### 2. GREEN — Implement to pass

- CoverMediaKind::PlainText is already in domain/types.rs.
- Import unicode_segmentation::UnicodeSegmentation. Use .graphemes(true) for iteration and capacity counting — not .chars() or .len().
- Capacity: cover.graphemes(true).count() / 8 bytes (1 bit per grapheme cluster).
- Injection: insert ZWSP (U+200B) = 0, ZWJ (U+200D) = 1 AFTER each grapheme cluster boundary. Never inside a cluster (this would corrupt emoji ZWJ sequences like 👨‍👩‍👧).
- Header: 32-bit length encoded first (32 clusters consumed).
- Reconstruction: collect graphemes, scan trailing ZWSP/ZWJ after each cluster, decode bits.
- Use str::floor_char_boundary and str::ceil_char_boundary (stable 1.91) if any byte-level slicing is absolutely required — document why at each use.
- fn strip_zero_width(text: &str) -> String: remove all ZWSP/ZWJ using a grapheme-aware pass.
- Test with Arabic, Devanagari, Thai, emoji ZWJ sequences, and RTL text.

### 3. REFACTOR — Clean up while green

- Remove duplication
- Improve naming and structure
- Keep all tests passing

## Housekeeping: TODO / FIXME Sweep

Before running preflight, scan all files you created or modified in this task for
`TODO`, `FIXME`, `HACK`, `XXX`, and similar markers.

- **Resolve** any that fall within the scope of this task's goal.
- **Leave in place** any that reference work belonging to a later task or phase — but ensure they include a task reference (e.g. `// TODO(T07): wire up auth adapter`).
- **Remove** any placeholder markers that are no longer relevant after your implementation.

If none are found, move on.

## Preflight

```bash
cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings
```

## Exit Criteria

- [ ] All code compiles without errors or warnings
- [ ] All tests pass
- [ ] Linter passes with no warnings
- [ ] Implementation matches the goal described above
- [ ] No unresolved TODO/FIXME/HACK markers that belong to this task's scope

## After Completion

Update PROGRESS.md row for T15 to `[x]`.
Commit: `feat(stego-zero-width): implement zero-width character text steganography with full unicode/grapheme safety`
