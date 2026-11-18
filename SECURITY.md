# Security Policy

## ⚠️ Pre-Production Status

**shadowforge has NOT been externally security audited.**

While it uses production-grade cryptography (NIST PQC standards: ML-KEM-1024,
ML-DSA-87), has comprehensive test coverage, and is designed for adversarial
environments, **do not use this software to protect life-critical communications
until Phase 18 (external audit) is complete.**

If you are a journalist or whistleblower in immediate danger:

- Use established, audited tools (Signal, Tor, SecureDrop) as your primary channel
- Consider shadowforge as a supplementary layer, not a replacement
- Read `OPERATIONAL_SECURITY.md` for threat-model-appropriate guidance

---

## Supported Versions

| Version | Security fixes | Notes |
|---------|----------------|-------|
| 0.4.x   | Yes            | Current release |
| 0.3.x   | No             | Upgrade for the fixes below |
| < 0.3   | No             | Not maintained |

Two defects in 0.3.x affect the confidentiality of the data you handle and
are fixed only in 0.4.0:

- **Encrypted PDFs lost their protection.** A PDF protected by an empty user
  password was reported as unprotected, accepted for embedding, and written
  back without its encryption. If you embedded a message into an encrypted
  document with 0.3.x, treat that document's confidentiality as compromised
  and re-encrypt it.
- **Archive extraction could write outside the target directory.** A crafted
  archive containing an entry named `../../etc/passwd` could write outside
  the directory you chose when unpacking. Archive handling in 0.4.0 confines
  every entry to the output directory.

Users of 0.3.x should upgrade rather than plan a backport.

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

6. **Encrypted PDFs are refused.** Since 0.4.0 the PDF techniques reject
   encrypted documents rather than risk writing one back out unprotected.
   Decrypt the document yourself first if you need to embed into it.

7. **The PDF content-stream payload format changed in 0.4.0.** A payload
   embedded with 0.3.x or earlier cannot be extracted with 0.4.0: the
   payload now carries a 32-bit length prefix, so the reader no longer
   mistakes the document's own coordinates for payload bytes. Extract your
   outstanding messages with 0.3.x before upgrading, or re-embed them.

8. **PDF content-stream capacity is small and document-dependent.** The
   technique stores one bit in the least significant bit of each numeric
   operand of a page's content stream, so a document's capacity is set by
   how much vector and text drawing it contains — a text-heavy page holds
   far more than an image-only one. `analyse` reports the measured figure;
   an image-only PDF may report no capacity at all.

9. **The `survivable` compression profile cannot be read back by the `lsb`
   extractor.** `embed-distributed --profile survivable` produces a cover
   that survives a JPEG round trip, but the `lsb` extractor accepts only
   PNG and BMP. The `dct` technique is the correct pairing for such a
   cover and is not yet implemented, so a `survivable` cover can be
   distributed but not yet extracted.

---

## Reporting Vulnerabilities

Please report security vulnerabilities **privately** via GitHub Security
Advisories: <https://github.com/greysquirr3l/shadowforge-rs/security/advisories/new>

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
- CI requires the pdfium shared library, so a broken pdfium binding fails
  the build instead of skipping the PDF tests
- The release workflow checks the tag, the crate version, the `VERSION`
  file and the changelog against each other before building anything
