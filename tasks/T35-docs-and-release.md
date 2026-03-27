# T35 — README, ARCHITECTURE.md, THREAT_MODEL.md, Makefile, and release workflow

> **Depends on**: T-cli.

## Goal

Write comprehensive documentation including a threat model targeting nation-state adversaries, an architecture diagram, and a release workflow for all platforms.

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

- CI: cargo deny check passes.
- CI: tarpaulin coverage >= 85% overall, >= 90% crypto.
- Release workflow: dry-run on PR (build only). Real upload on tag push.
- windows-arm64 (aarch64-pc-windows-msvc) builds cleanly — Tier 1 target.

### 2. GREEN — Implement to pass

- README.md: badges (Rust version, license, build, coverage), feature matrix vs Go version, quick-start for all major CLI paths. Prominent OPSEC warning: note pre-production status, no external audit yet.
- ARCHITECTURE.md: collapsed hexagonal diagram, bounded context map, data flow for embed/distribute/reconstruct pipelines, PDF pipeline diagram, nation-state countermeasure context map.
- THREAT_MODEL.md: explicit threat model sections — Automated Mass Steganalysis, Compelled Decryption, Traffic Analysis, Endpoint Compromise, Legal/Jurisdictional, Identity/Source Burning. For each: threat description, shadowforge-rs mitigations, residual risk, and operational guidance for journalists.
- OPERATIONAL_SECURITY.md: step-by-step guide for journalists. Covers: setting up dead drops, using deniable keys, distributing shards geographically, using time-lock for source protection, amnesiac mode at borders.
- Makefile targets: build, test, lint, clean, release, completions, deny, corpus-build-sample.
- GitHub Actions release.yml: trigger on tag v*. Build matrix: linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-x86_64, windows-arm64 (aarch64-pc-windows-msvc is Tier 1 as of 1.91). Attach binaries to GitHub Release.
- CHANGELOG.md: v0.1.0 entry listing all implemented features and threat model mitigations.
- SECURITY.md: security posture, pre-production status, planned audit, responsible disclosure.
- cargo-tarpaulin in CI: coverage >= 85% overall, >= 90% for crypto module.
- x86_64-apple-darwin is Tier 2 as of 1.90 — build it but note it in CI comments.

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

Update PROGRESS.md row for T35 to `[x]`.
Commit: `feat(docs-and-release): implement readme, architecture.md, threat_model.md, makefile, and release workflow`
