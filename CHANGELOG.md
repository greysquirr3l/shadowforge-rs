# Changelog

All notable changes to shadowforge are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## [0.3.4] — 2026-04-16

### Added

- **Security Audit workflow** — dedicated `security.yml` workflow runs
  Gitleaks secret scanning and `cargo audit` on every push to `main`, every PR,
  and on a weekly schedule
- **CodeQL Analysis workflow** — static analysis for Rust via GitHub's CodeQL
  engine on push, PR, and weekly schedule

### Fixed

- **Security Audit `checks: write` permission** — `rustsec/audit-check@v2`
  and `gitleaks-action` require `checks: write` to post Check Run annotations;
  the workflow previously only set `contents: read`, causing every audit run
  to fail with "Resource not accessible by integration"

### Security

- **Acknowledged transitive advisories in `deny.toml`** — `RUSTSEC-2026-0097`
  (`rand` unsound — aliased mutable reference under custom logger) and
  `RUSTSEC-2024-0384` (`instant` unmaintained) are pulled in transitively
  with no available patch from our side; both are documented with rationale
  in `deny.toml`

### Dependencies

- `codecov/codecov-action` 4 → 6
- `softprops/action-gh-release` 2.3.2 → 3.0.0
- `dependabot/fetch-metadata` 2 → 3
- `actions/deploy-pages` 4 → 5
- `actions/checkout` 4.2.2 → 6.0.2

## [0.3.3] — 2026-04-15

### Added

- **`PdfError::BindFailed` variant** — dedicated error variant for pdfium
  shared-library binding failures, distinct from `MalformedCoverData`; surfaces
  to users as `UnsupportedCoverType` so CLI/API consumers can distinguish setup
  problems from corrupted inputs
- **pdfium build-time auto-detection** — `build.rs` now checks for the pdfium
  shared library at build time (only when the `pdf` feature is enabled) and
  emits actionable `cargo:warning` messages when it is not found
- **`simd` feature documented** — added to the feature table in
  `docs/src/guide/installation.md` and `README.md`
- **`AppError::Cli` variant** — dedicated error variant for CLI validation and
  interface I/O failures, distinct from domain errors; all runner-side parse
  errors and filesystem errors now surface as `cli: {reason}` instead of
  leaking internal domain error types
- **Dependabot configuration** — weekly Cargo and GitHub Actions dependency
  updates; patch and minor bumps auto-merge once CI passes

### Changed

- **pdfium search paths expanded** — macOS search now includes
  `/opt/homebrew/lib` (Homebrew) and `/opt/local/lib` (MacPorts) in addition to
  `/usr/local/lib` and `/usr/lib`
- **`PDFIUM_DYNAMIC_LIB_PATH` uses `env::var_os`** — accepts any valid
  filesystem path, not only valid-UTF-8 paths
- **Build rerun trigger corrected** — replaced ineffective
  `cargo:rerun-if-changed=unknown` with `cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS`
- **`--no-default-features` warning clarified** — build warning now shows
  `--no-default-features --features corpus,adaptive` to disable only PDF rather
  than all features
- **`cargo install` package name corrected** — README and docs now reference
  `cargo install shadowforge` (matching `Cargo.toml` `name`) instead of
  `shadowforge-rs`
- **clap argument contracts tightened** — `--cover` and `--output` (embed) and
  `--input` and `--output` (extract) gain `conflicts_with = "amnesia"` so
  amnesiac mode has an unambiguous argument contract; `--deniable` gains
  `conflicts_with = "amnesia"` so the silently-ignored combination is rejected
  at parse time; `--platform` gains `required_if_eq("profile", "survivable")`
- **UTF-8 payload validation hardened** — `--scrub-style` now uses strict
  `String::from_utf8` rather than lossy conversion; binary payloads receive a
  clear error instead of silent data corruption
- **`--profile`/`--platform` single-cover embed** — now emits a compatibility
  warning pointing users to `embed-distributed` rather than hard-erroring

## [0.3.2] — 2026-04-15

### Security

- **rustls-webpki 0.103.10 → 0.103.12** — resolves RUSTSEC-2026-0098 (URI name
  constraints incorrectly accepted) and RUSTSEC-2026-0099 (wildcard certificate
  name constraint bypass); transitively pulled in via `ureq → rustls`

## [0.3.1] — 2026-04-15

### Fixed

- **Redundant clone removed** — `runner.rs` `cmd_extract_distributed` was
  cloning `hmac_key` into `RsErrorCorrector::new` unnecessarily; removed the
  redundant `.clone()` (clippy `redundant_clone` lint)
- **Formatting** — applied `cargo fmt` to `adapters/reconstruction.rs`

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

[Unreleased]: https://github.com/greysquirr3l/shadowforge-rs/compare/v0.3.4...HEAD
[0.3.4]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.4
[0.3.3]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.3
[0.3.2]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.2
[0.3.1]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.1
[0.3.0]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.0
[0.2.0]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.2.0
[0.1.0]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.1.0
