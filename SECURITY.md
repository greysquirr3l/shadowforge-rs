# Security Policy

## ⚠️ Pre-Production Status

**shadowforge-rs has NOT been externally security audited.**

While it uses production-grade cryptography (NIST PQC standards: ML-KEM-1024,
ML-DSA-87), has comprehensive test coverage, and is designed for adversarial
environments, **do not use this software to protect life-critical communications
until Phase 18 (external audit) is complete.**

If you are a journalist or whistleblower in immediate danger:
- Use established, audited tools (Signal, Tor, SecureDrop) as your primary channel
- Consider shadowforge-rs as a supplementary layer, not a replacement
- Read `OPERATIONAL_SECURITY.md` for threat-model-appropriate guidance

---

## Cryptographic Standards

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Key Encapsulation | ML-KEM-1024 | NIST FIPS 203 |
| Digital Signatures | ML-DSA-87 | NIST FIPS 204 |
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D |
| Key Derivation | Argon2id | RFC 9106 |
| Shard Integrity | HMAC-SHA256 | RFC 2104 |

All cryptographic comparisons use constant-time operations (`subtle` crate).
All key material is zeroized on drop (`zeroize` crate).

---

## Known Limitations

1. **Time-lock puzzles** do not provide cryptographic time-binding. A
   well-resourced adversary with faster hardware can solve them earlier than
   estimated. They provide practical, not absolute, time protection.

2. **Deniable steganography** provides plausible deniability against an
   adversary who does not hold the real key. It does not provide deniability
   against an adversary who holds both keys.

3. **Forensic watermark tripwires** do not survive platform recompression at
   quality settings below approximately 90. They are not suitable for
   identifying leaks via platforms that aggressively recompress images.

4. **Stylometric scrubbing** is statistical, not semantic. A sufficiently
   distinctive writing style with rare vocabulary not covered by the bundled
   frequency table may retain identifiable features.

5. **Corpus steganography** does not prevent an adversary from proving that a
   specific image was deliberately chosen if they have access to the full
   corpus and the payload's bit pattern.

---

## Reporting Vulnerabilities

Please report security vulnerabilities **privately** via GitHub Security
Advisories: https://github.com/greysquirr3l/shadowforge-rs/security/advisories/new

Do not open public issues for security vulnerabilities.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if known)

We will acknowledge receipt within 72 hours and aim to patch critical
vulnerabilities within 14 days.

---

## Planned Security Hardening (Phase 18)

- [ ] External cryptographic audit of the PQC integration
- [ ] Penetration testing of the CLI attack surface
- [ ] Formal verification of the deniable embedding scheme
- [ ] Side-channel analysis of key derivation and embedding operations
- [ ] Supply-chain audit (cargo-deny + manual review)

---

## Secure Development Practices

- All PRs require passing `cargo clippy -- -D warnings`
- `cargo deny check` enforces banned crates (no native-tls, no old PQC crates)
- `unsafe` code is `#![forbid(unsafe_code)]` at crate level; FFI adapters
  override this per-file with a safety comment requirement
- No secrets appear in tracing output at any log level
- CI runs on three platforms (Linux, macOS, Windows)
