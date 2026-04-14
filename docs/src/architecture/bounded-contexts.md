# Bounded Contexts

All bounded contexts live under `crates/shadowforge/src/domain/`. Each context owns its logic and types, interacting with the rest of the system through the shared type vocabulary (`types.rs`) and port traits (`ports.rs`).

## Core Contexts

| Context | Module | Responsibility |
|---------|--------|----------------|
| **Crypto** | `crypto/` | ML-KEM-1024 encapsulation, ML-DSA-87 signing, AES-256-GCM encryption, Argon2id key derivation |
| **Correction** | `correction/` | Reed-Solomon error correction, K-of-N shard splitting and recovery |
| **Stego** | `stego/` | 10 steganographic techniques: LSB (image), DCT (JPEG), palette, phase/echo/spread (audio), zero-width text, PDF content-stream LSB, PDF metadata, corpus selection |
| **Media** | `media/` | Image and audio format helpers (PNG, BMP, JPEG, GIF, WAV) |
| **PDF** | `pdf/` | PDF domain logic: embed/extract, page-render pipeline, content-stream LSB, metadata watermarking |
| **Distribution** | `distribution/` | Distribution patterns: 1:1, 1:N, N:1, N:M matrix |
| **Reconstruction** | `reconstruction/` | K-of-N shard reassembly with manifest verification |
| **Archive** | `archive/` | ZIP, TAR, TAR.GZ multi-carrier bundle support |
| **Analysis** | `analysis/` | Capacity estimation and chi-square detectability scoring |

## Nation-State Countermeasure Contexts

| Context | Module | Threat Addressed |
|---------|--------|------------------|
| **Adaptive** | `adaptive/` | Automated steganalysis (STC-inspired optimisation, cover profile matching, compression-survivable embedding) |
| **Deniable** | `deniable/` | Compelled decryption (dual-payload with plausible decoy) |
| **Canary** | `canary/` | Distribution compromise (canary shard tripwires) |
| **Dead Drop** | `deadrop/` | Traffic analysis (platform-aware cover generation for public posting) |
| **Time-Lock** | `timelock/` | Time-sensitive source protection (Rivest sequential squaring) |
| **Scrubber** | `scrubber/` | Stylometric identification (frequency-table normalisation) |
| **Corpus** | `corpus/` | Statistical stego signatures (zero-modification cover selection via ANN) |
| **Opsec** | `opsec/` | Endpoint compromise (amnesiac mode, panic wipe, geographic manifests, forensic watermarks) |

## Inter-Context Communication

Contexts do not import each other directly. Communication flows through:

1. **Shared types** in `domain/types.rs` — `Payload`, `Shard`, `CoverMedia`, `EncryptedPayload`, etc.
2. **Port traits** in `domain/ports.rs` — `Encryptor`, `Signer`, `SymmetricCipher`, `ErrorCorrector`, `MediaLoader`, etc.
3. **Application services** in `application/` — orchestrate multiple contexts by accepting port trait references.

This keeps each context independently testable and replaceable.
