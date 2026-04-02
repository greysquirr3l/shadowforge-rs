# Cryptographic Design

## Principles

1. **Post-quantum by default.** All asymmetric operations use NIST PQC finalists (ML-KEM, ML-DSA). No classical RSA or ECDH.
2. **Defense in depth.** Asymmetric encapsulation wraps a symmetric key; the payload itself is encrypted with AES-256-GCM.
3. **Constant-time everything.** Secret comparisons use `subtle::ConstantTimeEq`. No `==` on key bytes.
4. **Zeroize on drop.** Every struct holding key material or plaintext derives `ZeroizeOnDrop`.
5. **No secrets in logs.** Audit every `tracing::` call near key material.

## Algorithms

| Purpose | Algorithm | Crate | Notes |
|---------|-----------|-------|-------|
| Key encapsulation | ML-KEM-1024 | `ml-kem` | NIST FIPS 203 finalist |
| Digital signatures | ML-DSA-87 | `ml-dsa` | NIST FIPS 204 finalist |
| Symmetric encryption | AES-256-GCM | `aes-gcm` | 256-bit key, 96-bit nonce, authenticated |
| Key derivation | Argon2id | `argon2` | Memory-hard KDF for passphrase-based keys |
| Shard integrity | HMAC-SHA256 | `hmac` + `sha2` | Per-shard MAC for tamper detection |

## Key Lifecycle

```
keygen
  ├─ ML-KEM-1024 keypair  →  (encapsulation_key, decapsulation_key)
  └─ ML-DSA-87 keypair    →  (signing_key, verifying_key)

embed
  ├─ ML-KEM encapsulate(ek)           →  (ciphertext, shared_secret)
  ├─ Argon2id(shared_secret, salt)    →  symmetric_key
  ├─ AES-256-GCM encrypt(symmetric_key, nonce, payload)  →  encrypted_payload
  └─ ML-DSA sign(sk, encrypted_payload)                  →  signature

extract
  ├─ ML-DSA verify(vk, encrypted_payload, signature)
  ├─ ML-KEM decapsulate(dk, ciphertext)    →  shared_secret
  ├─ Argon2id(shared_secret, salt)         →  symmetric_key
  └─ AES-256-GCM decrypt(symmetric_key, nonce, encrypted_payload)  →  payload
```

## CryptoBundle Pattern

Application services never construct concrete crypto types. Instead, they receive a `CryptoBundle` containing trait references:

```rust
pub struct CryptoBundle<'a> {
    pub encryptor: &'a dyn Encryptor,
    pub signer:    &'a dyn Signer,
    pub cipher:    &'a dyn SymmetricCipher,
}
```

The CLI layer constructs concrete adapters and assembles the bundle. This keeps `domain/` and `application/` free of I/O and concrete crypto dependencies.
