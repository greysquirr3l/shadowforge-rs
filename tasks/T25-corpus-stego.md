# T25 — Zero-modification corpus steganography via ANN cover selection

> **Depends on**: T-stego-lsb-image, T-adaptive-embedding.

## Goal

Implement CorpusIndex and CorpusEmbedder: search a local image corpus for a cover whose natural bit pattern already encodes (or nearly encodes) the payload — minimising or eliminating modifications.

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

- build_index: index a directory of 10 test images, assert index contains 10 entries.
- search: insert a known image into the corpus, search for its exact payload pattern, assert it's returned as the top result with distance 0.
- CorpusEmbedder with perfect match: assert output is byte-identical to the original corpus image.
- CorpusEmbedder with no close match: assert falls back to LsbImage and payload is recoverable.
- Hamming distance calculation: unit test with known bit patterns.

### 2. GREEN — Implement to pass

- CorpusIndexImpl implements CorpusIndex in src/adapters/corpus.rs.
- Core idea: for a given payload, search the corpus for the image whose LSB pattern most closely matches the payload's bit pattern. If a perfect match exists, return that image unmodified — it is a valid stego cover that required zero modification.
- Index building (build_index): for each image in corpus_dir, compute a compact bit-pattern fingerprint (e.g., the first N LSBs of raw pixel data, stored as a bit vector). Store in an on-disk index (bincode-serialised HashMap<file_hash, CorpusEntry>).
- Search (search): given a payload, compute its bit pattern. Use approximate nearest-neighbour search (ANN) over the index — Hamming distance metric. A simple linear scan is acceptable for corpora up to ~100K images. For larger corpora, use a locality-sensitive hashing (LSH) table.
- CorpusEmbedder implements EmbedTechnique: 1) search corpus for closest match. 2) If Hamming distance == 0 (perfect match), return the original corpus image unmodified. 3) If Hamming distance > 0 but < threshold (e.g., < 5% of bits differ), apply minimal LsbImage embedding only for the differing positions. 4) If no close match, fall back to standard LsbImage.
- The capacity of CorpusSelection is the size of the payload that can be encoded in the first N pixels (same as LsbImage capacity).
- Security property: a corpus image returned with zero modification cannot be distinguished from any other image of its type — it IS an existing public image. The adversary must prove that a specific public image was deliberately chosen, which is a much higher legal and technical bar.
- Privacy: the corpus is local — no network calls to build or query the index. The user provides their own corpus (e.g., a local mirror of Flickr Creative Commons images).
- Add a CLI subcommand (Phase 13): shadowforge corpus build --dir <path> and shadowforge corpus stats.

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

Update PROGRESS.md row for T25 to `[x]`.
Commit: `feat(corpus-stego): implement zero-modification corpus steganography via ann cover selection`
