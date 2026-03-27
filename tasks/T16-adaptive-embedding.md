# T16 — Adversarial embedding optimisation (STC-inspired) and detectability minimisation

> **Depends on**: T-stego-lsb-image, T-stego-dct-jpeg, T-stego-audio, T-reed-solomon.

## Goal

Implement AdaptiveOptimiser: after any EmbedTechnique produces a stego cover, permute bit assignments to minimise statistical detectability against chi-square, RS analysis, and Sample Pair analysis.

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

- AdaptiveEmbedder round-trip: PNG cover, 64-byte payload, target -12dB, assert recovery.
- Assert chi_square_score(output) < chi_square_score(naive_embed) — adaptive is measurably better.
- Assert stego output still decodes correctly after optimisation (permutation is deterministic given the same key).
- Benchmark: document iteration count vs score improvement in a #[bench] test.

### 2. GREEN — Implement to pass

- AdaptiveOptimiserImpl implements AdaptiveOptimiser in src/adapters/adaptive.rs.
- Algorithm: 1) embed with the base technique. 2) score the output (chi-square, RS residual, Sample Pair asymmetry). 3) If score > target_db, generate candidate bit-position permutations (PRNG seeded from the crypto key) and score each. 4) Select the permutation with the lowest detectability score. 5) Re-embed with that permutation. Max iterations: configurable, default 100.
- This is inspired by Syndrome-Trellis Codes (STC) but does not require a full STC implementation — the permutation search is a practical approximation.
- Scoring functions: fn chi_square_score(original: &CoverMedia, stego: &CoverMedia) -> f64; fn rs_residual(stego: &CoverMedia) -> f64; fn sample_pair_asymmetry(stego: &CoverMedia) -> f64. Combine as weighted sum → dB score.
- Expose as a wrapper: AdaptiveEmbedder { inner: Box<dyn EmbedTechnique>, optimiser: Box<dyn AdaptiveOptimiser> } implementing EmbedTechnique. Transparent to the rest of the system.
- Document: this increases embed time O(iterations) but produces output that defeats commodity steganalysis tools (Aletheia, StegExpose).

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

Update PROGRESS.md row for T16 to `[x]`.
Commit: `feat(adaptive-embedding): implement adversarial embedding optimisation (stc-inspired) and detectability minimisation`
