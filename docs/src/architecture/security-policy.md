# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in shadowforge-rs, **do not open a public issue.** Instead:

1. Email the maintainers with a detailed description.
2. Include steps to reproduce the issue if possible.
3. Allow reasonable time for a fix before public disclosure.

We follow coordinated disclosure and will credit reporters unless they prefer anonymity.

## Supported Versions

Only the latest release on the `main` branch receives security patches. Pin your dependency to a specific version and update regularly.

## Threat Model Scope

shadowforge-rs is designed to resist:

- Automated steganalysis at infrastructure scale
- Compelled decryption at border crossings
- Traffic analysis and sender-recipient correlation
- Endpoint compromise and memory forensics
- Jurisdictional legal pressure across multiple countries
- Stylometric source identification

For the full threat model, see the [Threat Model](../threats/overview.md) section.

## Cryptographic Choices

- **Post-quantum only.** ML-KEM-1024 and ML-DSA-87 (NIST PQC finalists). No classical algorithms.
- **No custom cryptography.** All primitives come from audited Rust crates (`ml-kem`, `ml-dsa`, `aes-gcm`, `argon2`).
- **Constant-time comparisons** via `subtle::ConstantTimeEq` on all secret material.
- **Secure zeroing** via `zeroize` and `ZeroizeOnDrop` on all key material and plaintext buffers.

## Supply Chain

- `cargo-deny` enforces banned crate policies (`deny.toml`).
- No `native-tls`, `openssl-sys`, `pqcrypto`, or `oqs` dependencies.
- Dependabot alerts are monitored. Yanked crates are blocked.

## Unsafe Code

- `#![forbid(unsafe_code)]` is set at the crate root.
- The only exception is `adapters/pdf.rs` for pdfium-render FFI bindings.
- Any `unsafe extern` block requires a safety comment and explicit review.
