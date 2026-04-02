# shadowforge-rs

**Quantum-resistant steganography toolkit for journalists, whistleblowers, and dissidents operating against nation-state adversaries.**

> **Pre-audit software.** shadowforge-rs has not yet undergone a formal cryptographic or security audit. Use it as a supplementary layer alongside established tools (Signal, Tor, Tails) — never as a sole protection mechanism.

shadowforge-rs is a ground-up Rust reimplementation of [shadowforge](https://github.com/greysquirr3l/shadowforge) (Go), designed for the journalist-vs-nation-state threat model.

## What It Does

shadowforge-rs hides encrypted payloads inside ordinary-looking cover media (images, audio, PDFs, text) using steganographic techniques that resist automated detection. It then layers post-quantum cryptography, forward error correction, and operational security countermeasures on top.

## Key Capabilities

| Capability | Description |
|-----------|-------------|
| **10 steganographic techniques** | LSB image, DCT JPEG, palette, audio (LSB/phase/echo), zero-width text, PDF content-stream, PDF metadata, corpus selection |
| **Post-quantum cryptography** | ML-KEM-1024 (key encapsulation), ML-DSA-87 (signatures) — pure Rust, no liboqs |
| **Reed-Solomon error correction** | K-of-N shard splitting with HMAC integrity verification |
| **Deniable steganography** | Dual-payload embedding — reveal a decoy under compulsion |
| **Dead drop mode** | Platform-aware cover generation for public posting (no direct file transfer) |
| **Time-lock puzzles** | Rivest sequential-squaring payloads that can't be opened early |
| **Stylometric scrubbing** | Normalise writing patterns to resist authorship attribution |
| **Amnesiac mode** | Zero disk writes — entire pipeline runs through `std::io::pipe()` |
| **Canary shards** | Tripwire detection for compromised distribution channels |
| **Geographic distribution** | Jurisdiction-threshold manifests requiring shards from multiple countries |
| **Forensic watermarks** | Unique recipient fingerprints to trace leaks |
| **Panic wipe** | Emergency 3-pass secure deletion of key material |

## Design Principles

- **Threat-first**: Every feature maps to a specific adversary capability.
- **Zero panics**: No `.unwrap()`, `.expect()`, or unchecked indexing in production code — including tests.
- **Pure domain**: The domain layer contains zero I/O. All external interaction goes through port traits.
- **Unicode safe**: All text operations use grapheme clusters. Arabic, Thai, Devanagari, and emoji ZWJ sequences work correctly.
- **Post-quantum only**: No RSA, no ECDSA, no X25519. ML-KEM and ML-DSA exclusively.
