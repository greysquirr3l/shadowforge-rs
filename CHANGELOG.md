# Changelog

All notable changes to shadowforge are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## [0.4.0] — 2026-11-17

### Security

- **Encrypted PDFs are rejected instead of silently unprotected** — the
  check consulted `is_encrypted()`, but lopdf decrypts a document whose
  user password is empty as it loads and then drops the `/Encrypt` entry
  from the trailer, so the flag was already false by the time the code
  looked. A document that was encrypted was reported as unprotected,
  accepted for embedding, and written back without its protection.
  `load_pdf` now consults `was_encrypted()` as well, and refuses
  encrypted documents outright.

- **Path traversal via ZIP entry names** — `unpack_zip` took the raw
  entry name and the CLI wrote it to `output_dir.join(name)`, so a crafted
  archive containing an entry named `../../etc/passwd` wrote outside the
  directory the user chose. Entry names are now resolved through
  `enclosed_name()`, falling back to `mangled_name()`, which cannot
  resolve above the output directory. Covered by a new test.

### Fixed

- **Rebuilt PDFs pointed at the wrong objects** — the page dictionary and
  its content stream were addressed by guessing object IDs as offsets
  from the page's own ID. lopdf allocates IDs on insertion, so the
  guesses landed on unrelated objects: a page's `/Contents` pointed at the
  page dictionary, and the image XObject pointed at the content stream.
  The rebuilt document is now structurally valid.

- **Rebuilt PDFs declared the wrong stream filter** — the image XObject
  was declared `FlateDecode` but held PNG bytes, so a renderer decoded
  the data as zlib and produced a blank page. The image is now stored as
  a `DCTDecode` JPEG XObject, which is what it always was.

- **The second pdfium render in a process always failed** — pdfium keeps
  its bindings in a global `OnceCell`, so it can only be bound once per
  process. A second bind attempt returned
  `PdfiumLibraryBindingsAlreadyInitialized`, which the code treated as
  fatal, so any workflow that rendered pages twice — the render pipeline
  followed by a cover rebuild — failed at the second call. The bound
  library is now cached and shared.

- **PDF content-stream capacity bore no relation to what could be
  embedded** — the reported figure came from a heuristic that divided the
  file size by 80, while the embedder stores one bit in the least
  significant bit of each *numeric operand* of a page's content stream.
  The two disagreed by orders of magnitude: `analyse` reported 573 bytes
  for a document that could hold 2. Capacity is now measured from the
  document's own content streams, and `analyse`, `capacity()` and
  `embed` all report the same figure.

- **Extracting a content-stream payload returned trailing garbage** —
  the payload carried no length prefix, so the reader could not tell
  where it ended and kept consuming the document's own operands: a
  five-byte message came back as ten bytes, the second five being
  fragments of the page's coordinates. The payload is now framed with a
  32-bit big-endian length, matching the header the image and audio
  techniques already use.

- **Content-stream embedding corrupted the document's images** — the
  embedder wrote into every stream in the file, including the
  FlateDecode-compressed image XObjects. A bit written into compressed
  data changes the bytes the decoder sees, which shows up as a visibly
  broken page. Embedding and extraction are now confined to the page's
  content streams.

- **Compression-survivable covers failed outright** — the compression
  simulator read RGBA cover data as RGB and returned RGB, which shifted
  every channel and left the buffer a quarter too short for every
  downstream reader. `embed-distributed --profile survivable` failed with
  an image-dimension error. The simulator now converts to RGB properly
  and returns RGBA, matching the `CoverMedia` convention.

- **`cargo deny` now passes** — the dependency refresh resolved 20+ outstanding
  advisories (including the `zip` extraction symlink and `flate2`
  decompression advisories, and the `crossbeam-epoch` pointer-dereference
  issue) along with three yanked crates. The remaining `chrono`
  unmaintained advisory (RUSTSEC-2026-0543) is explicitly ignored with a
  rationale: it has no fixed release and arrives transitively through
  `lopdf` and `pdfium-render`, so it cannot be removed without dropping PDF
  support.

- **Argon2id key derivation migrated to `hash_password_into`** — argon2 0.6
  removed the `hash_password`/`SaltString` API. The replacement takes the
  raw salt bytes directly instead of round-tripping them through base64.
  Derived keys are byte-identical to the previous implementation, so
  existing payloads remain decryptable.

- **AES-256-GCM key and nonce construction moved to `TryFrom`** — aes-gcm
  0.11 deprecated `Array::from_slice`. Length mismatches now surface as
  the existing `InvalidKeyLength` / `InvalidNonceLength` errors instead of
  panicking.

- **New clippy lints from the 1.98 toolchain** — `chunks_exact` with a
  constant chunk size (now `as_chunks`), `suboptimal_flops` (now
  `mul_add`), and a missing `#[must_use]` are all fixed rather than
  suppressed, keeping `cargo clippy -- -D warnings` green.

### Changed

- **Workspace switches to `resolver = "3"`** — Cargo's MSRV-aware
  resolver prefers dependency versions that still support the declared
  `rust-version`, instead of silently selecting newer ones that require a
  newer compiler. The pinned toolchain stays at 1.94.1: the update to the
  latest dependency set raises the highest MSRV among transitive
  dependencies only to 1.89, so the existing floor still holds.

- **Dropped `vergen` in favour of the `git` CLI** — vergen 10 moved git
  support into a separate crate that links libgit2, which is a heavy C
  dependency for embedding a single commit SHA. The build script now
  shells out to `git` directly, matching the pattern used by the
  project's other Rust workspaces, and reports `"unknown"` rather than
  failing the build when git is unavailable (source tarballs, minimal
  containers). The embedded SHA also carries a `-dirty` suffix when the
  working tree had uncommitted changes at build time.

- **Removed the dead workspace-root `build.rs`** — the workspace root is a
  virtual manifest (no `[package]`), so this file was never compiled or
  executed. It was a leftover vergen build script.

- **Removed the `[patch.crates-io]` override for `pdfium-render`** — the
  override existed to carry an upstream `c_char` fix (E0308 on platforms
  where `c_char` is unsigned) that was not yet released. `pdfium-render`
  0.9.3 ships the fix, and the crate is now used at the released 0.9.5
  with no patch. The `deny.toml` git-source allowance that only existed
  for this override was removed with it.

- **Updated dependencies to their latest compatible versions** — `lopdf`
  0.42 → 0.47, `aes-gcm` 0.10 → 0.11, `argon2` 0.5 → 0.6, `zip` 8 → 9,
  `base64` 0.22 → 0.23, `num-bigint` 0.4 → 0.5, `ml-kem` 0.3.2 → 0.3.4,
  `ml-dsa` 0.1.1 → 0.1.2, `rstest` 0.26 → 0.28, and the full transitive
  graph. `cargo outdated --root-deps-only` now reports every root
  dependency current.

- **Disabled CodeQL `rust/hard-coded-cryptographic-value` query** — all 26
  open alerts were the same false-positive pattern (test fixtures like
  `let key = vec![0u8; 32];` or zero-initialised buffers immediately
  overwritten by RNG/SHA256). Configured via
  `.github/codeql/codeql-config.yml` and dismissed as `false positive`.
  See the config file for the rationale and the alternative controls
  (`unsafe_code = "forbid"`, `cargo-deny`, `gitleaks`, code review)
  that still cover any real hard-coded-key regression.

### Testing

- **The three ignored PDF tests are enabled** — they were marked
  `#[ignore]` with a note that the behaviour was unimplemented, but they
  were in fact exposing the defects above. All three pass.

- **CI requires pdfium** — the PDF tests skip themselves when the pdfium
  shared library is absent, which meant a broken pdfium binding could
  hide behind a skip. The CI workflow now sets `SHADOWFORGE_REQUIRE_PDFIUM`,
  which turns the skip into a failure where pdfium is installed.

- **The release workflow verifies the version before publishing** — the
  tag, the crate version, the `VERSION` file and the changelog are
  checked against each other before anything is built, so a mismatched
  release can no longer reach crates.io.

## [0.3.7] — 2026-06-26

### Security

- **Eliminated RUSTSEC-2026-0187 exposure** — bumped `lopdf` from `0.41` to
  `0.42`. The 0.41 line parses PDF arrays and dictionaries with unbounded
  recursion; a crafted ~21 KB PDF with ~10,380-deep nested arrays aborts the
  process via SIGABRT (uncatchable with `catch_unwind`), enabling trivial
  DoS against any service parsing untrusted PDFs. Fixed upstream in 0.42.0.

- **Disabled CodeQL `rust/hard-coded-cryptographic-value` query** — all 26
  open alerts were the same false-positive pattern (test fixtures like
  `let key = vec![0u8; 32];` or zero-initialised buffers immediately
  overwritten by RNG/SHA256). Configured via
  `.github/codeql/codeql-config.yml` and dismissed as `false positive`.
  See the config file for the rationale and the alternative controls
  (`unsafe_code = "forbid"`, `cargo-deny`, `gitleaks`, code review)
  that still cover any real hard-coded-key regression.

### Fixed

- **Build break on `main`** — migrated `domain/crypto/mod.rs` from the
  `ml-dsa 0.1.0-rc.8` API surface (`KeyGen` trait, `MlDsa87::key_gen` /
  `from_seed` static methods) to the `ml-dsa 0.1.1` surface
  (`SigningKey::<P>::from_seed`, explicit seed-fill via `rand::RngExt::fill`
  for keygen). The source had drifted from the pinned crate version, so a
  fresh `cargo check` failed — which in turn was blocking every open
  Dependabot PR.
- **Missing `hmac::KeyInit` import** — `hmac 0.13` requires the `KeyInit`
  trait to be in scope for `Hmac::new_from_slice`. Added the import in
  `domain/correction/mod.rs`.
- **Clippy `cast_sign_loss` on `i32` page index** — replaced
  `page_index as usize` with `usize::try_from(page_index).unwrap_or(0)` in
  `adapters/pdf.rs` (4 sites). Pre-existing warnings that would have failed
  CI once the build was restored.
- **aarch64-linux-gnu cross-build failure** — `pdfium-render 0.9.2` hardcodes
  `chars.as_ptr() as *const i8` in `fpdf_sys_font_info_get_face_name`, but
  `c_char` is `u8` (not `i8`) on aarch64/ARM Linux (also PPC, RISC-V,
  s390x). The cast mismatches the `*mut c_char` buffer and rustc fails
  with E0308 under the `cross` tool image. Pinned upstream's one-character
  fix (`as *const c_char`) via `[patch.crates-io]` to commit `095024c`;
  the fix is on master but not yet released. Drop the patch entry when
  `pdfium-render 0.9.3` ships.

### Changed

- `actions/checkout` 4.2.2 → 7.0.0 (#34)
- `codecov/codecov-action` 6 → 7 (#28)
- `gitleaks/gitleaks-action` 2 → 3 (#26)

## [0.3.6] — 2026-05-07

### Security

- **Eliminated RUSTSEC-2026-0097 exposure path** — removed the unused `num-bigint`
  `rand` feature, which eliminated the transitive `rand 0.8.5` dependency from
  the workspace dependency graph

- **Disabled CodeQL `rust/hard-coded-cryptographic-value` query** — all 26
  open alerts were the same false-positive pattern (test fixtures like
  `let key = vec![0u8; 32];` or zero-initialised buffers immediately
  overwritten by RNG/SHA256). Configured via
  `.github/codeql/codeql-config.yml` and dismissed as `false positive`.
  See the config file for the rationale and the alternative controls
  (`unsafe_code = "forbid"`, `cargo-deny`, `gitleaks`, code review)
  that still cover any real hard-coded-key regression.

### Fixed

- **Version alignment** — synchronized repository release marker in `VERSION`
  with crate versioning (`0.3.6`)
- **`cargo-deny` advisory config cleanup** — removed stale advisory ignores from
  `deny.toml` after dependency and advisory state changes; `cargo deny check advisories`
  now passes cleanly without advisory ignore entries

## [0.3.5] — 2026-04-22

- **Disabled CodeQL `rust/hard-coded-cryptographic-value` query** — all 26
  open alerts were the same false-positive pattern (test fixtures like
  `let key = vec![0u8; 32];` or zero-initialised buffers immediately
  overwritten by RNG/SHA256). Configured via
  `.github/codeql/codeql-config.yml` and dismissed as `false positive`.
  See the config file for the rationale and the alternative controls
  (`unsafe_code = "forbid"`, `cargo-deny`, `gitleaks`, code review)
  that still cover any real hard-coded-key regression.

### Fixed

- **`cargo-deny` toolchain mismatch** — replaced `EmbarkStudios/cargo-deny-action@v2`
  with an explicit toolchain install + `cargo install cargo-deny --locked`; the
  action was resolving to a musl target that did not match the pinned 1.94.1
  toolchain, causing every Supply Chain CI job to fail
- **`cargo deny` flag ordering** — corrected invocation to
  `cargo deny --all-features check` (global flag must precede the subcommand;
  `cargo deny check --all-features` is rejected by the CLI)
- **Security Audit `issues: write` permission** — `rustsec/audit-check@v2`
  requires `issues: write` to file issues for new advisories; absence caused
  "Resource not accessible by integration" on every audit run

### Security

- **rustls-webpki 0.103.12 → 0.103.13** — patches RUSTSEC-2026-0104 (reachable
  panic in CRL parsing); pulled in transitively via `ureq → rustls`

### Changed

- `actions/checkout` 4.2.2 → 6.0.2 (security.yml)
- `github/codeql-action` 3 → 4
- `actions/upload-pages-artifact` 3 → 5

## [0.3.4] — 2026-04-16

### Added

- **Security Audit workflow** — dedicated `security.yml` workflow runs
  Gitleaks secret scanning and `cargo audit` on every push to `main`, every PR,
  and on a weekly schedule
- **CodeQL Analysis workflow** — static analysis for Rust via GitHub's CodeQL
  engine on push, PR, and weekly schedule

- **Disabled CodeQL `rust/hard-coded-cryptographic-value` query** — all 26
  open alerts were the same false-positive pattern (test fixtures like
  `let key = vec![0u8; 32];` or zero-initialised buffers immediately
  overwritten by RNG/SHA256). Configured via
  `.github/codeql/codeql-config.yml` and dismissed as `false positive`.
  See the config file for the rationale and the alternative controls
  (`unsafe_code = "forbid"`, `cargo-deny`, `gitleaks`, code review)
  that still cover any real hard-coded-key regression.

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

### Changed

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

- **Disabled CodeQL `rust/hard-coded-cryptographic-value` query** — all 26
  open alerts were the same false-positive pattern (test fixtures like
  `let key = vec![0u8; 32];` or zero-initialised buffers immediately
  overwritten by RNG/SHA256). Configured via
  `.github/codeql/codeql-config.yml` and dismissed as `false positive`.
  See the config file for the rationale and the alternative controls
  (`unsafe_code = "forbid"`, `cargo-deny`, `gitleaks`, code review)
  that still cover any real hard-coded-key regression.

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

- **Disabled CodeQL `rust/hard-coded-cryptographic-value` query** — all 26
  open alerts were the same false-positive pattern (test fixtures like
  `let key = vec![0u8; 32];` or zero-initialised buffers immediately
  overwritten by RNG/SHA256). Configured via
  `.github/codeql/codeql-config.yml` and dismissed as `false positive`.
  See the config file for the rationale and the alternative controls
  (`unsafe_code = "forbid"`, `cargo-deny`, `gitleaks`, code review)
  that still cover any real hard-coded-key regression.

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

[Unreleased]: https://github.com/greysquirr3l/shadowforge-rs/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/greysquirr3l/shadowforge-rs/compare/v0.3.7...v0.4.0
[0.3.7]: https://github.com/greysquirr3l/shadowforge-rs/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/greysquirr3l/shadowforge-rs/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/greysquirr3l/shadowforge-rs/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.4
[0.3.3]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.3
[0.3.2]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.2
[0.3.1]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.1
[0.3.0]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.3.0
[0.2.0]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.2.0
[0.1.0]: https://github.com/greysquirr3l/shadowforge-rs/releases/tag/v0.1.0
