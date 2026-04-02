# Changelog

All notable changes to shadowforge-rs are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

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

---

## [0.1.0] — TBD

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

[Unreleased]: https://github.com/greysquirr3l/shadowforge-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.1.0
