# Changelog

All notable changes to shadowforge-rs are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## [0.3.0] — 2026-04-14

### Added

- **ML-DSA sign/verify CLI workflows** — `keygen sign` and `keygen verify`
  subcommands exposed, enabling signing arbitrary payloads and verifying
  detached ML-DSA-87 signatures directly from the CLI
- **Spectral adaptive embedding primitives** — introduced AI-generator-aware
  profile vocabulary (`AiGenProfile`, `CarrierBin`, `CoverProfile`,
  `SpectralKey`) to model known FFT carrier regions and resolution-specific
  watermark behavior
- **Adaptive bounded context implementation** — added
  `domain/adaptive/mod.rs` with frequency-bin masking and STC-inspired
  permutation search (`BinMask`, `SearchConfig`, `permutation_search`)
- **Adaptive adapter implementations** — added `AdaptiveOptimiserImpl`,
  `CoverProfileMatcherImpl`, and `CompressionSimulatorImpl` with bundled AI
  profile codebook support
- **Corpus spectral secondary index** — `CorpusIndex` now supports
  model-aware lookup via `search_for_model` and index introspection via
  `model_stats`
- **Corpus CLI model filtering** — `corpus search` now accepts optional
  `--model` and `--resolution` filters for generator-aware cover selection

### Changed

- **Analysis report extended** — `AnalysisReport` now includes optional
  `spectral_score` alongside existing detectability metrics
- **Corpus entry enrichment** — `CorpusEntry` now carries an optional
  `spectral_key` field for future generator-aware enrichment; corpus
  indexing currently sets it to `None` (bucketing is reserved for a
  future indexing pass)

### Refactored

- **Geographic distribution boundary hardened** — `DistributeService` now
  exposes `distribute_with_geographic_manifest`, routing geo-threshold
  distribution through the application service layer rather than calling the
  adapter port directly from the runner; eliminates an interface→adapter
  boundary violation
- **Hexagonal architecture wiring audited** — verified all adapter instantiation
  points in runner.rs, eliminated dead code (PDF stego duplicates), and enforced
  strict dependency injection for ErrorCorrector across distribution and
  reconstruction services

### Testing

- **Spectral/adaptive phase validated** — T36–T40 implementation passed full
  workspace validation: 453 tests passing, 0 failures, and clippy clean with
  0 warnings
- **Documentation audit complete** — verified all references to port traits,
  test counts, and architecture documentation; updated README badge (387 → 453),
  CHANGELOG test counts, and bounded contexts terminology

## [0.2.0] — 2026-04-10

### Added

- **mdbook documentation site** — 39 pages covering user guide, CLI reference,
  threat model, architecture, and contributing guidelines; published to
  GitHub Pages via `docs.yml` workflow
- **Shell completions** — `completions` subcommand now takes shell as a
  positional argument; added `--output` flag to write directly to a file
- **PDF install instructions** in README — pdfium binary download for
  macOS (ARM/Intel) and Linux with `PDFIUM_DYNAMIC_LIB_PATH` setup
- `make book` / `make book-serve` Makefile targets for local mdbook builds

### Changed

- **Tiered documentation publishing** — operational playbooks (`docs/src/opsec/`)
  excluded from the published site to avoid exposing user behaviour patterns;
  accessible only by cloning the repository
- README overhauled: fixed broken image tag and dead links (`ARCHITECTURE.md`,
  `docs/install-pdfium.md`), added docs site link, shell completions section,
  inline PDF setup, and contributing guide link
- `OPERATIONAL_SECURITY.md` moved to gitignore (content preserved in
  `docs/src/opsec/` for repo cloners)

### Fixed

- **Lint hardening** — enabled `clippy::pedantic` and denied `expect_used`,
  `unwrap_used`, `indexing_slicing` in Cargo.toml workspace lints; fixed 461
  violations across 26 files (zero clippy warnings from CLI and IDE)
- Replaced all `.unwrap()` / `.expect()` in non-test code with `?` or
  explicit error handling
- Replaced all direct indexing (`&vec[i]`, `&s[0..n]`) with `.get()` and
  explicit bounds handling

### Testing

- **Test coverage maintained at 85%** — 380 tests in this phase (now 453 total with T36–T40 AI watermark phase)
- Added 128 new unit tests across all adapter and domain modules:
  application/services (34 tests, 100%), domain/analysis (98.6%),
  domain/crypto (93.5%), domain/distribution (89.2%), domain/types (100%),
  adapters/stego (84.5%), adapters/media (86.4%), adapters/archive (86%),
  adapters/opsec (88%), adapters/distribution (82.4%)
- Added `tarpaulin.toml` to exclude CLI dispatch layer from coverage metrics

### Security

- **Hardcoded HMAC key replaced** — `DistributorImpl` now generates a random
  32-byte HMAC key per session (or accepts one via `--hmac-key`); key persisted
  alongside the output archive for reconstruction
- **cargo-deny config fixed** — `unmaintained` field updated for v2 schema,
  deprecated `deny` key removed, missing transitive licenses added
  (CC0-1.0, MIT-0, CDLA-Permissive-2.0, bzip2-1.0.6); supply chain checks
  now run cleanly (advisories ok, bans ok, licenses ok, sources ok)
- **Panic wipe no longer leaks file paths** — removed `eprintln!` calls that
  printed key/config/temp-dir paths to stderr during emergency wipe
- **Pre-release crypto deps pinned** — `ml-kem` and `ml-dsa` locked to exact
  RC versions to prevent silent upgrades
- **Archive entry reads bounded** — zip/tar/tar.gz unpacking capped at
  256 MiB per entry via `Read::take()` to prevent zip-bomb DoS
- **stdin read bounded** — amnesia-mode extract capped at 256 MiB
- **Dead `bincode` dependency removed** — unused crate eliminated from the
  dependency tree

---

## [0.1.0] — 2026-04-02

### Added

#### Core Bounded Contexts

- ML-KEM-1024 key encapsulation (NIST FIPS 203)
- ML-DSA-87 digital signatures (NIST FIPS 204)
- AES-256-GCM symmetric encryption with Argon2id KDF
- Reed-Solomon K-of-N erasure coding with HMAC-tagged shards
- 10 steganographic techniques: LSB-image, DCT-JPEG, Palette, LSB-audio,
  Phase-DSSS, Echo-hiding, Zero-width-text, PDF-content-stream,
  PDF-metadata, Corpus-selection
- First-class PDF bounded context: load/save, page rasterisation,
  content-stream LSB, XMP metadata watermarking, shard-per-page pipeline
- Four distribution patterns: 1:1, 1:N (K-of-N), N:1, N:M matrix
- ZIP, TAR, TAR.GZ archive handling with nested archive support
- Capacity estimation and chi-square detectability analysis

#### Nation-State Countermeasures

- Adversarial embedding optimisation (STC-inspired, defeats Aletheia/StegExpose)
- Camera model fingerprint matching for JPEG covers
- Compression-survivable embedding for Instagram, Twitter, WhatsApp,
  Telegram, and Imgur
- Deniable dual-payload steganography (plausible deniability under compulsion)
- Panic wipe: 3-pass overwrite, exits 0 silently
- Dead drop mode: platform-aware public-posting workflow
- Canary shard tripwires for distribution compromise detection
- Time-lock puzzle payloads (Rivest sequential squaring)
- Linguistic stylometric fingerprint scrubbing
- Zero-modification corpus steganography via ANN cover selection
- Amnesiac mode: zero disk writes via `std::io::pipe()`
- Geographic threshold distribution manifests
- Forensic watermark tripwires for leak attribution

#### Documentation

- `THREAT_MODEL.md`: 7 threat classes with mitigations and residual risks
- `OPERATIONAL_SECURITY.md`: Step-by-step journalist guide for 5 scenarios
- `ARCHITECTURE.md`: Collapsed hexagonal / DDD-lite design rationale

### Security

- All key material `ZeroizeOnDrop` throughout
- Constant-time comparisons via `subtle` crate
- No secrets in tracing output
- `cargo deny` supply chain policy enforced in CI
- `#![forbid(unsafe_code)]` at crate level

### Notes

- Pre-production: external security audit pending (planned for v0.2.0)
- PDF support requires pdfium system library — see README for installation

[Unreleased]: https://github.com/greysquirr3l/shadowforge-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.2.0
[0.1.0]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.1.0
