# T23 — Time-lock puzzle payloads using Rivest iterated hash chains

> **Depends on**: T-crypto-symmetric.

## Goal

Implement TimeLockService: a payload cannot be decrypted before a specified time, even under compulsion. Uses Rivest's sequential squaring time-lock puzzle.

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

- lock with unlock_at = now + 1 second: unlock after 1 second succeeds.
- lock with unlock_at = now + 1 hour: try_unlock returns Ok(None) immediately.
- Round-trip: lock, then unlock, assert payload identity.
- TimeLockPuzzle serialises to JSON cleanly (large integers as hex strings).
- Benchmark test: document measured squarings/sec on the CI machine.

### 2. GREEN — Implement to pass

- TimeLockServiceImpl implements TimeLockService in src/adapters/timelock.rs.
- Algorithm: Rivest-Shamir-Wagner time-lock puzzle (1996). 1) Generate a random 2048-bit RSA modulus n = p*q. 2) Compute the number of sequential squarings required to delay decryption until unlock_at (calibrate against a benchmark of squarings/second on the expected hardware — store this as a constant, default ~10M squarings/sec). 3) Encrypt payload with AES-256-GCM using a key derived from the final value of repeated squaring. 4) The puzzle contains: n (modulus), start_value, squarings_required, ciphertext. The secret key p*q is discarded after puzzle creation.
- lock: generate puzzle. The sender can publish the puzzle immediately — it reveals nothing until squarings_required sequential steps are completed.
- unlock: perform the sequential squarings (CPU-bound, cannot be parallelised), derive the AES key, decrypt. Returns Err(TimeLockError::NotYetUnlockable { estimated_remaining_secs }) if benchmarked completion time is still in the future.
- try_unlock: non-blocking check — returns Ok(None) if not yet solvable by current hardware estimate.
- Use case: a journalist embeds a time-locked payload that their source can prove they cannot read until the story goes live. Also: self-destruct by deadline (if not retrieved by T, the puzzle takes too long to solve).
- Security note: time-lock puzzles do not provide cryptographic time-binding — a well-resourced adversary with faster hardware can solve them earlier. Document this clearly. The scheme provides practical but not absolute time protection.
- num-bigint or rug crate for big integer arithmetic. rug (GMP bindings) is faster but has C FFI — document in build notes.

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

Update PROGRESS.md row for T23 to `[x]`.
Commit: `feat(time-lock): implement time-lock puzzle payloads using rivest iterated hash chains`
