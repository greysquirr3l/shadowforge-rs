# T33 — Use-case orchestrators for all services including nation-state countermeasures

> **Depends on**: T-distribution, T-reconstruction, T-analysis, T-archive, T-pdf-pipeline, T-deniable-stego, T-panic-wipe, T-canary-shards, T-dead-drop, T-time-lock, T-stylo-scrubber, T-corpus-stego, T-forensic-watermark-tripwire.

## Goal

Wire all bounded contexts into thin application services. No file I/O. CryptoBundle passed by reference throughout.

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

- EmbedService + ExtractService: PNG, 32-byte payload, LsbImage.
- EmbedService with Adaptive profile: assert AnalysisReport shows lower detectability than Standard.
- DistributeService + ReconstructService: 3 PNG covers, OneToMany, drop 1, reconstruct.
- DeniableEmbedService: embed dual, extract with each key, assert different payloads.
- DeadDropService: output survives simulated Instagram compression.
- TimeLockService: lock with 1-second delay, unlock after waiting, assert payload.
- ScrubService: scrubbed text has lower stylometric distinctiveness.
- ForensicService: embed 3 tripwires, identify correct recipient.

### 2. GREEN — Implement to pass

- EmbedService: embed(cover, payload, technique, crypto) -> Result<CoverMedia, AppError>.
- EmbedService also accepts EmbeddingProfile — dispatches to AdaptiveEmbedder or CompressionSurvivableEmbedder based on profile.
- ExtractService: extract(stego, technique, crypto) -> Result<Payload, AppError>.
- KeyGenService: generate_keypair(algorithm) -> Result<KeyPair, AppError>.
- WatermarkService: embed/extract/verify watermarks.
- DistributeService: distribute(payload, covers, pattern, technique, crypto, options: DistributeOptions) -> Result<DistributeResult, AppError>. DistributeOptions: { canary: bool, geo_manifest: Option<GeoManifestInput>, profile: EmbeddingProfile }. DistributeResult: { covers, canary_shard, geo_manifest }.
- ReconstructService: reconstruct(stego_covers, technique, crypto) -> Result<Payload, AppError>.
- AnalyseService: analyse(cover, technique) -> Result<AnalysisReport, AppError>.
- DeniableEmbedService: embed_dual(cover, pair, keys, technique) -> Result<CoverMedia, AppError>; extract_deniable(stego, key, technique) -> Result<Payload, AppError>.
- DeadDropService: encode(cover, payload, platform, crypto) -> Result<(CoverMedia, RetrievalManifest), AppError>.
- TimeLockService: lock(payload, unlock_at) / unlock(puzzle) / try_unlock(puzzle).
- ScrubService: scrub(text, profile) -> Result<String, AppError>.
- CorpusService: build_index(dir) / search(payload, technique) / embed_via_corpus(payload, technique, crypto).
- ForensicService: embed_tripwire(cover, tag) / identify_recipient(stego, tags).
- AmnesiaPipelineService: embed_in_memory / extract_in_memory.
- PanicWipeService: wipe(config).
- AppError wraps all domain errors via thiserror #[from].
- No file I/O in application/ — callers (CLI) load/save via MediaLoader/PdfProcessor adapters.

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

Update PROGRESS.md row for T33 to `[x]`.
Commit: `feat(application-services): implement use-case orchestrators for all services including nation-state countermeasures`
