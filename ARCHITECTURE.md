# Architecture

shadowforge-rs uses a **Collapsed Hexagonal / DDD-lite** layout inside a
Cargo workspace mono-repo. All crates live under `crates/`. The current
production crate is `crates/shadowforge`; future crates (`shadowforge-web`,
`shadowforge-api`, etc.) add as new members without restructuring anything.

---

## Module Tree

```
crates/shadowforge/src/
├── lib.rs               ← crate root; #![forbid(unsafe_code)]
├── main.rs              ← binary entry point; instantiates adapters, calls CLI
│
├── domain/              ← PURE — zero I/O, zero tokio, zero std::fs
│   ├── types.rs         ← single canonical type vocabulary (CoverMedia, Payload, …)
│   ├── ports.rs         ← all object-safe port traits
│   ├── errors.rs        ← all domain error types (thiserror)
│   ├── crypto/          ← ML-KEM-1024, ML-DSA-87, Argon2id, AES-256-GCM
│   ├── correction/      ← Reed-Solomon K-of-N
│   ├── stego/           ← 10 embedding techniques
│   ├── media/           ← image/audio type helpers
│   ├── pdf/             ← PDF domain helpers (no I/O)
│   ├── distribution/    ← 4 distribution patterns + geo-manifest
│   ├── reconstruction/  ← K-of-N shard reassembly
│   ├── archive/         ← ZIP / TAR / TAR.GZ helpers
│   ├── analysis/        ← capacity estimation, chi-square scoring
│   ├── adaptive/        ← STC-inspired optimisation helpers
│   ├── deniable/        ← dual-payload scheme helpers
│   ├── canary/          ← canary shard tripwire helpers
│   ├── deadrop/         ← dead-drop pipeline helpers
│   ├── timelock/        ← Rivest iterated hash-chain logic
│   ├── scrubber/        ← stylometric normalisation logic
│   ├── corpus/          ← corpus index domain types
│   └── opsec/           ← geographic manifests, forensic watermark helpers
│
├── adapters/            ← I/O allowed; all port-trait implementations
│   ├── crypto.rs        ← MlKemEncryptor, MlDsaSigner, Aes256GcmCipher
│   ├── media.rs         ← ImageMediaLoader, AudioMediaLoader
│   ├── pdf.rs           ← PdfProcessorImpl (lopdf + pdfium-render)
│   ├── stego.rs         ← all 10 StegoService impls
│   ├── distribution.rs  ← DistributorImpl (4 patterns), GeographicDistributorImpl
│   ├── reconstruction.rs← ReconstructorImpl
│   ├── archive.rs       ← ArchiveServiceImpl (zip/tar/tar.gz)
│   ├── corpus.rs        ← CorpusIndexImpl (linear ANN scan)
│   ├── adaptive.rs      ← AdaptiveOptimiserImpl, CoverProfileMatcherImpl
│   ├── deniable.rs      ← DeniableEmbedderImpl
│   ├── canary.rs        ← CanaryServiceImpl
│   ├── deadrop.rs       ← DeadDropEncoderImpl
│   ├── timelock.rs      ← TimeLockServiceImpl
│   ├── scrubber.rs      ← StyloScrubberImpl
│   └── opsec.rs         ← PanicWiperImpl, AmnesiaPipelineImpl, ForensicWatermarkerImpl
│
├── application/         ← Thin orchestration; accepts port-trait refs; no I/O
│   └── services/        ← EmbedService, ExtractService, DistributeService, …
│
└── interface/
    ├── cli.rs           ← clap (derive) command definitions
    └── runner.rs        ← command dispatch; loads files; calls application services
```

---

## Dependency Rule

```
interface/ ──► application/ ──► domain/ ◄── adapters/
```

Adapters implement the port traits declared in `domain/ports.rs`. The
application layer calls domain through those traits; it never imports an
adapter type directly. The interface layer wires concrete adapters to
application services and is the only layer permitted to touch the filesystem.

---

## Collapsed Hexagonal Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│  interface/  (CLI + runner)                                              │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  application/  (use-case orchestrators)                           │  │
│  │  ┌──────────────────────────────────────────────────────────────┐ │  │
│  │  │  domain/  (pure business logic + port traits)                │ │  │
│  │  └──────────────────────────────────────────────────────────────┘ │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  adapters/  (port-trait implementations; I/O lives here)                 │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Bounded Contexts

### Core

| Context | Location | Responsibility |
|---------|----------|----------------|
| `crypto` | `domain/crypto/` + `adapters/crypto.rs` | ML-KEM-1024 KEM, ML-DSA-87 signing, AES-256-GCM cipher, Argon2id KDF |
| `correction` | `domain/correction/` | Reed-Solomon K-of-N erasure coding, HMAC-tagged shards |
| `stego` | `domain/stego/` + `adapters/stego.rs` | 10 embedding techniques (see below) |
| `media` | `domain/media/` + `adapters/media.rs` | PNG/BMP/JPEG/GIF image loading; WAV audio loading |
| `pdf` | `domain/pdf/` + `adapters/pdf.rs` | PDF load/save, page rasterisation, content-stream LSB, XMP metadata |
| `distribution` | `domain/distribution/` + `adapters/distribution.rs` | 4 patterns: 1:1, 1:N, N:1, N:M; geographic manifests |
| `reconstruction` | `domain/reconstruction/` | K-of-N shard reassembly with manifest verification |
| `archive` | `domain/archive/` + `adapters/archive.rs` | ZIP / TAR / TAR.GZ multi-carrier bundles |
| `analysis` | `domain/analysis/` | Capacity estimation, chi-square detectability scoring |

### Nation-State Countermeasures

| Context | Location | Responsibility |
|---------|----------|----------------|
| `adaptive` | `domain/adaptive/` + `adapters/adaptive.rs` | STC-inspired permutation optimisation; camera-model fingerprint matching; compression-survivable embedding |
| `deniable` | `domain/deniable/` + `adapters/deniable.rs` | Dual-payload deniable steganography; plausible decoy under compulsion |
| `canary` | `domain/canary/` + `adapters/canary.rs` | Canary shard tripwires; distribution compromise detection via HTTP |
| `deadrop` | `domain/deadrop/` + `adapters/deadrop.rs` | Dead drop mode; platform-aware public-posting cover generation |
| `timelock` | `domain/timelock/` + `adapters/timelock.rs` | Rivest sequential-squaring time-lock puzzles |
| `scrubber` | `domain/scrubber/` + `adapters/scrubber.rs` | Linguistic stylometric fingerprint scrubbing |
| `corpus` | `domain/corpus/` + `adapters/corpus.rs` | Zero-modification cover selection via ANN corpus search |
| `opsec` | `domain/opsec/` + `adapters/opsec.rs` | Amnesiac mode, geographic threshold manifests, forensic watermark tripwires, panic wipe |

---

## Steganographic Techniques

| Technique | Struct | Cover Type | Notes |
|-----------|--------|------------|-------|
| LSB image | `LsbImageStegoService` | PNG/BMP | Full implementation |
| DCT JPEG | `DctJpegStegoService` | JPEG | Stubbed — pure-Rust DCT coefficient access pending |
| Palette | `PaletteStegoService` | GIF/PNG | Stubbed — palette extraction pending |
| LSB audio | `LsbAudioStegoService` | WAV | Full implementation |
| Phase encoding (DSSS) | `PhaseEncodingStegoService` | WAV | Stubbed |
| Echo hiding | `EchoHidingStegoService` | WAV | Stubbed |
| Zero-width text | `ZeroWidthStegoService` | Text | Stubbed — grapheme-safe ZWJ boundary logic pending |
| PDF content-stream LSB | `PdfContentStreamStegoService` | PDF | Full implementation |
| PDF XMP metadata | `PdfMetadataStegoService` | PDF | Full implementation |
| Corpus selection | `CorpusStegoService` | Any image | Full implementation |

---

## Embed Pipeline (Core Path)

```
┌─────────────────────────────────────────────────────────────────────┐
│ interface/runner.rs                                                  │
│  1. Load cover file(s) from disk                                     │
│  2. Read plaintext payload                                           │
│  3. Build CryptoBundle { encryptor, signer, cipher }                │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
            ┌───────────────────▼──────────────────┐
            │ application/services/EmbedService     │
            │  1. Argon2id KDF → session key        │
            │  2. Optionally: StyloScrubber         │
            │  3. AES-256-GCM encrypt payload       │
            │  4. ML-DSA-87 sign ciphertext         │
            │  5. Reed-Solomon K-of-N shard         │
            │  6. Select StegoService per technique  │
            │  7. Embed each shard in a cover       │
            │  8. Optionally: AdaptiveEmbedder      │
            └───────────────────┬──────────────────┘
                                │
            ┌───────────────────▼──────────────────┐
            │ adapters/stego.rs                     │
            │  LsbImageStegoService.embed()         │
            │   (or PDF, audio, corpus, …)          │
            └──────────────────────────────────────┘
```

---

## Distribute Pipeline

```
┌────────────────────────────────────────────────────────────────────┐
│ interface/runner.rs                                                 │
│  1. Load stego covers from disk / glob                             │
│  2. Parse distribution args (pattern, shards, geo-manifest, …)     │
└──────────────────────────┬─────────────────────────────────────────┘
                           │
           ┌───────────────▼────────────────────┐
           │ adapters/distribution.rs            │
           │  DistributorImpl                    │
           │  ├── OneToOne  (1 cover → 1 dest)   │
           │  ├── OneToMany (1 cover → K-of-N)   │
           │  ├── ManyToOne (N covers → 1 dest)  │
           │  └── ManyToMany (N×M matrix)        │
           │                                     │
           │  Optional:                          │
           │  ├── CanaryService (add tripwire)   │
           │  └── GeographicDistributorImpl      │
           └────────────────────────────────────┘
```

---

## PDF Pipeline

```
PDF file
  └─► PdfProcessorImpl.load_pdf()          (lopdf — parse + page count)
        │
        ├─► rasterise_pages()              (pdfium-render — page → PNG)
        │     │
        │     └─► [PNG image per page]
        │           │
        │           └─► LsbImageStegoService.embed()  (one shard per page)
        │
        └─► PdfProcessorImpl.rebuild_pdf()  (lopdf — reassemble modified pages)
              └─► Output stego PDF
```

---

## CryptoBundle Pattern

All application services receive cryptographic dependencies as a bundle,
not as individual injected parameters. This prevents constructing concrete
crypto types inside the domain or application layers:

```rust
pub struct CryptoBundle<'a> {
    pub encryptor: &'a dyn Encryptor,
    pub signer:    &'a dyn Signer,
    pub cipher:    &'a dyn SymmetricCipher,
}
```

The `CryptoBundle` is assembled in `interface/runner.rs` from concrete adapter
types, then passed down through the application layer.

---

## Key Design Constraints

| Rule | Rationale |
|------|-----------|
| `domain/` is I/O-free | Enables pure-Rust testing without mocking filesystems; enforces hexagonal boundary |
| `#![forbid(unsafe_code)]` at crate root | FFI (`pdfium-render`) overrides per-file only; all other code is safe Rust |
| `ZeroizeOnDrop` on all key-material structs | Reduces window for memory-forensics exfiltration |
| `subtle::ConstantTimeEq` for secret comparisons | Defeats timing side-channels |
| `strict_add` / `strict_sub` / `strict_mul` for capacity arithmetic | Explicit panic on overflow rather than silent wrapping in security calculations |
| `.graphemes(true)` for all text iteration | Grapheme-cluster-safety for Arabic, Thai, Devanagari, emoji ZWJ inputs |
| No `tokio` — `rayon` for parallelism | Keeps the runtime model synchronous and predictable; adapters use blocking I/O |

---

*Last updated: April 2026 | Rust 1.94.1 | Edition 2024*
