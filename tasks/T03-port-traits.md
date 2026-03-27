# T03 — Port trait definitions in domain/ports.rs

> **Depends on**: T-domain-types.

## Goal

Define all object-safe port traits for all bounded contexts including the new nation-state countermeasure contexts.

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

- Compile-time object-safety check for every trait.
- All error variants serialise to JSON without panicking.

### 2. GREEN — Implement to pass

- Encryptor: encapsulate(public_key) -> Result<(Bytes, Bytes), CryptoError>; decapsulate(secret_key, ciphertext) -> Result<Bytes, CryptoError>.
- Signer: sign(key, message) -> Result<Signature, CryptoError>; verify(key, message, sig) -> Result<bool, CryptoError>.
- SymmetricCipher: encrypt(key, nonce, plaintext) -> Result<Bytes, CryptoError>; decrypt(key, nonce, ciphertext) -> Result<Bytes, CryptoError>.
- ErrorCorrector: encode(data, data_shards, parity_shards) -> Result<Vec<Shard>, CorrectionError>; decode(shards, data_shards, parity_shards) -> Result<Bytes, CorrectionError>.
- EmbedTechnique: technique() -> StegoTechnique; capacity(cover) -> Result<Capacity, StegoError>; embed(cover, payload) -> Result<CoverMedia, StegoError>.
- ExtractTechnique: technique() -> StegoTechnique; extract(stego) -> Result<Payload, StegoError>.
- MediaLoader: load(path) -> Result<CoverMedia, MediaError>; save(media, path) -> Result<(), MediaError>.
- PdfProcessor: load_pdf(path) -> Result<CoverMedia, PdfError>; save_pdf(media, path) -> Result<(), PdfError>; render_pages_to_images(pdf) -> Result<Vec<CoverMedia>, PdfError>; rebuild_pdf_from_images(images, original) -> Result<CoverMedia, PdfError>; embed_in_content_stream(pdf, payload) -> Result<CoverMedia, PdfError>; extract_from_content_stream(pdf) -> Result<Payload, PdfError>; embed_in_metadata(pdf, payload) -> Result<CoverMedia, PdfError>; extract_from_metadata(pdf) -> Result<Payload, PdfError>.
- Distributor: distribute(payload, pattern, covers, embedder) -> Result<Vec<CoverMedia>, DistributionError>.
- Reconstructor: reconstruct(shards, extractor, progress_cb) -> Result<Payload, ReconstructionError>.
- CapacityAnalyser: analyse(cover, technique) -> Result<AnalysisReport, AnalysisError>.
- ArchiveHandler: pack(files, format) -> Result<Bytes, ArchiveError>; unpack(archive, format) -> Result<Vec<(String, Bytes)>, ArchiveError>.
- AdaptiveOptimiser: optimise(stego: CoverMedia, original: &CoverMedia, target_db: f64) -> Result<CoverMedia, AdaptiveError>.
- CoverProfileMatcher: profile_for(cover: &CoverMedia) -> Option<CameraProfile>; apply_profile(cover: CoverMedia, profile: &CameraProfile) -> Result<CoverMedia, AdaptiveError>. CameraProfile is a domain type holding quantisation table + noise floor.
- CompressionSimulator: simulate(cover: CoverMedia, platform: &PlatformProfile) -> Result<CoverMedia, AdaptiveError>; survivable_capacity(cover: &CoverMedia, platform: &PlatformProfile) -> Result<Capacity, AdaptiveError>.
- DeniableEmbedder: embed_dual(cover: CoverMedia, pair: &DeniablePayloadPair, keys: &DeniableKeySet, embedder: &dyn EmbedTechnique) -> Result<CoverMedia, DeniableError>; extract_with_key(stego: &CoverMedia, key: &[u8], extractor: &dyn ExtractTechnique) -> Result<Payload, DeniableError>.
- PanicWiper: wipe(config: &PanicWipeConfig) -> Result<(), OpsecError>. Must be synchronous and infallible in practice — log errors but complete all wipe steps.
- CanaryService: embed_canary(covers: Vec<CoverMedia>, embedder: &dyn EmbedTechnique) -> Result<(Vec<CoverMedia>, CanaryShard), CanaryError>; check_canary(shard: &CanaryShard) -> bool.
- DeadDropEncoder: encode_for_platform(cover: CoverMedia, payload: &Payload, platform: &PlatformProfile, embedder: &dyn EmbedTechnique) -> Result<CoverMedia, DeadDropError>.
- TimeLockService: lock(payload: &Payload, unlock_at: DateTime<Utc>) -> Result<TimeLockPuzzle, TimeLockError>; unlock(puzzle: &TimeLockPuzzle) -> Result<Payload, TimeLockError>; try_unlock(puzzle: &TimeLockPuzzle) -> Result<Option<Payload>, TimeLockError>.
- StyloScrubber: scrub(text: &str, profile: &StyloProfile) -> Result<String, ScrubberError>.
- CorpusIndex: search(payload: &Payload, technique: StegoTechnique, max_results: usize) -> Result<Vec<CorpusEntry>, CorpusError>; add_to_index(path: &Path) -> Result<CorpusEntry, CorpusError>; build_index(corpus_dir: &Path) -> Result<usize, CorpusError>.
- CorpusEmbedder implements EmbedTechnique: selects a corpus cover, returns it unmodified if full pre-match achieved, else minimal modification.
- AmnesiaPipeline: embed_in_memory(input: impl Read, cover_input: impl Read, output: impl Write, technique: &dyn EmbedTechnique, crypto: &CryptoBundle) -> Result<(), OpsecError>. No temp files created.
- ForensicWatermarker: embed_tripwire(cover: CoverMedia, tag: &WatermarkTripwireTag) -> Result<CoverMedia, OpsecError>; identify_recipient(stego: &CoverMedia, tags: &[WatermarkTripwireTag]) -> Result<Option<WatermarkTripwireTag>, OpsecError>.
- All port traits must be object-safe — write _assert_object_safe() compile-time checks for each.
- All error types in domain/errors.rs using thiserror.

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

Update PROGRESS.md row for T03 to `[x]`.
Commit: `feat(port-traits): implement port trait definitions in domain/ports.rs`
