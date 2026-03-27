# shadowforge-rs — Implementation Progress

> Orchestrator reads this file at the start of each loop iteration.
> Subagents update this file after completing a task.

## Status Legend

- `[ ]` — Not started
- `[~]` — In progress (claimed by a subagent)
- `[x]` — Completed
- `[!]` — Blocked / needs human input

---

## Phase 1 — Workspace Scaffold

| Task | Status | Notes |
| --- | --- | --- |
| T01 — Workspace skeleton, toolchain pin, CI, and lint config | `[x]` | |

---

## Phase 2 — Shared Domain Types

> Depends on: Phase 1 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T02 — Canonical type vocabulary in domain/types.rs | `[x]` | |
| T03 — Port trait definitions in domain/ports.rs | `[x]` | |

---

## Phase 3 — Crypto Bounded Context

> Depends on: Phase 2 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T04 — ML-KEM-1024 and ML-DSA-87 implementations | `[x]` | |
| T05 — AES-256-GCM symmetric cipher, Argon2id KDF, and full pipeline helpers | `[x]` | |

---

## Phase 4 — Error Correction Bounded Context

> Depends on: Phase 3 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T06 — Reed-Solomon K-of-N erasure coding with HMAC-tagged shards | `[x]` | |

---

## Phase 5 — Media Bounded Context

> Depends on: Phase 4 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T07 — Image and audio codec adapters | `[x]` | |

---

## Phase 6 — PDF Bounded Context

> Depends on: Phase 5 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T08 — PDF load/save and page-render-to-image pipeline | `[x]` | |
| T09 — PDF-native stego: content-stream LSB and XMP metadata watermarking | `[ ]` | |
| T10 — PDF render-stego-rebuild pipeline and distribution integration | `[ ]` | |

---

## Phase 7 — Steganography Bounded Context

> Depends on: Phase 6 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T11 — LSB image steganography (PNG/BMP) | `[ ]` | |
| T12 — DCT-based JPEG steganography | `[ ]` | |
| T13 — Palette-based steganography (GIF/PNG indexed) | `[ ]` | |
| T14 — LSB audio, phase encoding (DSSS), and echo hiding (WAV) | `[ ]` | |
| T15 — Zero-width character text steganography with full Unicode/grapheme safety | `[ ]` | |

---

## Phase 8 — Adaptive Embedding Bounded Context

> Depends on: Phase 7 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T16 — Adversarial embedding optimisation (STC-inspired) and detectability minimisation | `[ ]` | |
| T17 — Camera model fingerprint matching for JPEG stego covers | `[ ]` | |
| T18 — Compression-survivable embedding for social media platform recompression | `[ ]` | |

---

## Phase 9 — Deniable Steganography and Panic Wipe

> Depends on: Phase 8 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T19 — Dual-payload deniable steganography | `[ ]` | |
| T20 — Panic wipe: emergency secure erasure of all key material | `[ ]` | |

---

## Phase 10 — Canary Shards and Dead Drop Mode

> Depends on: Phase 9 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T21 — Canary shard tripwires for K-of-N distribution compromise detection | `[ ]` | |
| T22 — Dead drop mode: platform-aware cover generation for public posting | `[ ]` | |

---

## Phase 11 — Time-Lock Payloads and Stylometric Scrubbing

> Depends on: Phase 10 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T23 — Time-lock puzzle payloads using Rivest iterated hash chains | `[ ]` | |
| T24 — Linguistic stylometric fingerprint scrubbing | `[ ]` | |

---

## Phase 12 — Corpus Steganography

> Depends on: Phase 11 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T25 — Zero-modification corpus steganography via ANN cover selection | `[ ]` | |

---

## Phase 13 — Operational Security Context

> Depends on: Phase 12 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T26 — Amnesiac mode: zero-disk-write in-memory pipeline via std::io::pipe | `[ ]` | |
| T27 — Geographic threshold distribution manifests | `[ ]` | |
| T28 — Forensic watermark tripwires for distribution leak identification | `[ ]` | |

---

## Phase 14 — Distribution and Reconstruction

> Depends on: Phase 13 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T29 — Four distribution patterns: 1:1, 1:N, N:1, N:M — with canary and geographic support | `[ ]` | |
| T30 — K-of-N shard reconstruction with full verification chain | `[ ]` | |

---

## Phase 15 — Analysis and Archive

> Depends on: Phase 14 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T31 — Capacity estimation and chi-square detectability analysis across all techniques | `[ ]` | |
| T32 — ZIP and TAR/TAR.GZ archive handling with nested archive support | `[ ]` | |

---

## Phase 16 — Application Layer

> Depends on: Phase 15 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T33 — Use-case orchestrators for all services including nation-state countermeasures | `[ ]` | |

---

## Phase 17 — CLI Interface

> Depends on: Phase 16 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T34 — Full clap CLI: Go surface + all nation-state countermeasure commands | `[ ]` | |

---

## Phase 18 — Documentation and Release Hygiene

> Depends on: Phase 17 all complete

| Task | Status | Notes |
| --- | --- | --- |
| T35 — README, ARCHITECTURE.md, THREAT_MODEL.md, Makefile, and release workflow | `[ ]` | |

---

## Accumulated Learnings

> Subagents append discoveries here after each task.
> The orchestrator reads this section at the start of every iteration
> to avoid repeating past mistakes.

- T02: `RUSTFLAGS=-D warnings` in shell promotes `missing_docs = "warn"` to a hard error — every public variant, field, and method needs a doc comment.
- T02: Compact single-line enum variant syntax (`OneToMany { x: u8 }`) cannot hold per-field doc comments — always expand to multi-line form.
- T02: `bytes::Bytes` needs `features = ["serde"]` for `Serialize`/`Deserialize`.
- T02: `Uuid` from the `uuid` crate does NOT implement `Zeroize` — use manual `impl Zeroize + Drop + Clone` when a struct containing `Uuid` needs zeroization.
- T02: `ml-kem` and `ml-dsa` parameter sets are Rust types, not Cargo features — never add feature flags for them.
- T02: `bincode 3.0.0` is intentionally uncompilable (ships a `compile_error!`) — keep `bincode = "1"`.
- T02: `vergen 9` moved git support to companion crates (`vergen-gitcl`, `vergen-git2`) that only have beta releases — keep vergen at `"8"` with `features = ["git", "gitcl"]`.
- T02: `ureq 3` has no `tls` feature; `rustls` is on by default — use `ureq = "3"` with no extra features.
- T02: `lopdf 0.40` removed the `nom_parser` feature (nom is the default parser) — do not specify it.
- T02: `sha2 0.11` requires `digest 0.11`; `hmac 0.13` is still rc — keep the entire RustCrypto digest-0.10 family in sync (`sha2 = "0.10"`, `hmac = "0.12"`, `aes-gcm = "0.10"`, `argon2 = "0.5"`).
- T03: `thiserror` was missing from `Cargo.toml` — always check that every `use` in domain/ has a corresponding dep entry.
- T03: `AmnesiaPipeline::embed_in_memory` must use `&mut dyn Read` / `&mut dyn Write` (not `impl Trait`) to remain object-safe.
- T03: Port traits referencing `Box<dyn Fn(...)>` in signatures break object safety — use `&dyn Fn(...)` instead.
- T03: `CameraProfile` belongs in `ports.rs` (not `types.rs`) because it is adapter-facing configuration, not a domain value.
- T03: Object-safety is best verified with a single test that calls `fn assert_object_safe<T: ?Sized>()` for every trait — compile-time check with zero runtime cost.
- T04: `rand_core 0.10` does NOT have `from_entropy()` or `from_os_rng()` — use `ChaCha20Rng::from_rng(&mut rand::rng())` to seed from OS entropy.
- T04: `bytes::Bytes` is immutable and cannot be mutated or zeroized — for tests, remove zeroize calls or convert to `Vec<u8>` first.
- T05: Argon2id requires `PasswordHasher` trait to be in scope to use `hash_password()` method.
- T05: `Payload` is a newtype `Payload(Vec<u8>)` — use `from_bytes()` to construct and `as_bytes()` to access data.
- T05: Use `#[expect(clippy::cast_possible_truncation, reason = "...")]` for intentional casts with documented bounds.
- T06: Use `.flatten()` on iterators of `Option` to avoid manual `if let Some` patterns (clippy::manual_flatten).
- T06: CorrectionError::HmacMismatch uses field name `index` not `shard_index`.
- T07: MediaError::IoError only has a `reason` field (not `path` or `source`) — use `MediaError::IoError { reason: e.to_string() }`.
- T08: lopdf has `new_object_id()` not `new_page_id()` — use `new_object_id()` to reserve object IDs before referencing them.
- T08: `dictionary!` macro must be imported explicitly — add `use lopdf::dictionary;`.
- T08: pdfium-render requires system library installation — mark tests with `#[ignore = "requires pdfium system library"]` when unavailable.
- T08: In edition 2024, `ref mut` on already-borrowed mutable references is redundant — use `if let Object::Dictionary(dict) = pages_dict` when `pages_dict` is `&mut _`.
