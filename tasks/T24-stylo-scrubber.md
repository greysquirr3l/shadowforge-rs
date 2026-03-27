# T24 — Linguistic stylometric fingerprint scrubbing

> **Depends on**: T-port-traits.

## Goal

Implement StyloScrubber: normalise a text payload to destroy authorship attribution fingerprints without changing meaning.

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

- Scrub a known author's distinctive text: assert word frequency distribution is closer to the reference corpus than the original.
- Sentence length normalisation: input with sentences of [5, 50, 3, 45] words produces output with average near target_avg_sentence_len.
- Punctuation normalisation: input with smart quotes → ASCII quotes in output.
- Idempotent: scrub(scrub(text)) == scrub(text).
- Non-Latin input (Arabic, Chinese): passes through without modification and without panic.
- Grapheme-safe: all tokenisation uses unicode-segmentation.

### 2. GREEN — Implement to pass

- StyloScrubberImpl implements StyloScrubber in src/adapters/scrubber.rs.
- Stylometric features to neutralise: word frequency distribution, average sentence length, punctuation patterns, rare word choices, paragraph structure.
- Algorithm: 1) Tokenise input text into sentences and words using a Unicode-aware tokeniser. 2) Replace rare words (frequency < threshold in a reference corpus) with their most common synonym from a compact synonym table bundled with the binary. 3) Normalise sentence lengths toward StyloProfile.target_avg_sentence_len by splitting long sentences at conjunctions and merging short ones. 4) Normalise punctuation: standardise em-dashes to --, ellipses to ..., smart quotes to ASCII. 5) Standardise contractions (don't → do not or vice versa, consistently).
- Reference corpus: bundle a compact word-frequency table derived from a public corpus (e.g., Wikipedia word frequencies, top 50K words with frequencies). Compile in via include_bytes! as a sorted binary lookup table.
- This is NOT an LLM. It is a deterministic statistical normalisation. No network calls, no model inference.
- Unicode-aware tokenisation: use the unicode-segmentation crate for sentence boundaries and word boundaries. Handle multi-language input gracefully — fall back to no-op for non-Latin scripts where normalisation is not applicable.
- Idempotent: scrubbing an already-scrubbed text returns the same result.

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

Update PROGRESS.md row for T24 to `[x]`.
Commit: `feat(stylo-scrubber): implement linguistic stylometric fingerprint scrubbing`
