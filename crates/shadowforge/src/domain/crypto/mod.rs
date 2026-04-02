//! ML-KEM-1024, ML-DSA-87, Argon2id, AES-256-GCM, and secure zeroing.
//!
//! All functions are pure — no I/O, no file system, no network. Each
//! function that needs randomness accepts a CSPRNG as a parameter so it
//! can be exercised with a seeded RNG in tests.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key as AesKey, KeyInit, Nonce};
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHasher};
use bytes::{BufMut, Bytes, BytesMut};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa87, VerifyingKey, signature::Keypair,
};
use ml_kem::{
    Decapsulate, DecapsulationKey1024, Encapsulate as _, EncapsulationKey1024, Kem as _, Key,
    KeyExport as _, MlKem1024,
};
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::domain::errors::CryptoError;
use crate::domain::types::{KeyPair, Payload, Signature};

/// Expected byte-length of an ML-KEM-1024 seed (secret key stored form).
const KEM_SEED_LEN: usize = 64;
/// Expected byte-length of an ML-KEM-1024 encapsulation (public) key.
const KEM_EK_LEN: usize = 1568;
/// Expected byte-length of an ML-DSA-87 seed (secret key stored form).
const DSA_SEED_LEN: usize = 32;
/// Expected byte-length of an ML-DSA-87 verifying (public) key.
const DSA_VK_LEN: usize = 2592;
/// AES-256 key length in bytes.
const AES_KEY_LEN: usize = 32;
/// AES-GCM nonce length in bytes.
const AES_NONCE_LEN: usize = 12;
/// Argon2id salt length in bytes.
const ARGON2_SALT_LEN: usize = 32;

// ─── ML-KEM-1024 (NIST FIPS 203) ─────────────────────────────────────────────

/// Generate an ML-KEM-1024 key pair using the provided CSPRNG.
///
/// The returned [`KeyPair`] stores the 64-byte compact seed as `secret_key`
/// and the 1568-byte encapsulation key as `public_key`. Both fields are
/// zeroized on drop.
///
/// # Errors
/// Returns [`CryptoError::KeyGenFailed`] if the freshly generated key does
/// not carry a recoverable seed (should never occur in practice).
pub fn generate_kem_keypair(rng: &mut impl CryptoRng) -> Result<KeyPair, CryptoError> {
    let (dk, ek) = MlKem1024::generate_keypair_from_rng(rng);
    let seed = dk.to_seed().ok_or_else(|| CryptoError::KeyGenFailed {
        reason: "freshly generated key has no seed".into(),
    })?;
    let ek_bytes = ek.to_bytes();
    Ok(KeyPair {
        public_key: (ek_bytes.as_ref() as &[u8]).to_vec(),
        secret_key: (seed.as_ref() as &[u8]).to_vec(),
    })
}

/// Encapsulate a shared secret for the holder of `public_key`.
///
/// Returns `(ciphertext, shared_secret)` — both as raw bytes.
/// Ciphertext is 1568 bytes; shared secret is 32 bytes.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] if `public_key` is not 1568
/// bytes, or [`CryptoError::EncapsulationFailed`] if the key bytes are
/// otherwise invalid.
pub fn encapsulate_kem(
    public_key: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<(Bytes, Bytes), CryptoError> {
    if public_key.len() != KEM_EK_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEM_EK_LEN,
            got: public_key.len(),
        });
    }
    let key_arr: Key<EncapsulationKey1024> =
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: KEM_EK_LEN,
                got: public_key.len(),
            })?;
    let ek = EncapsulationKey1024::new(&key_arr).map_err(|_| CryptoError::EncapsulationFailed {
        reason: "invalid encapsulation key".into(),
    })?;
    let (ct, ss) = ek.encapsulate_with_rng(rng);
    Ok((
        Bytes::copy_from_slice(ct.as_ref() as &[u8]),
        Bytes::copy_from_slice(ss.as_ref() as &[u8]),
    ))
}

/// Decapsulate a shared secret using `secret_key` (the 64-byte seed) and
/// `ciphertext`.
///
/// ML-KEM uses implicit rejection — an invalid ciphertext yields a
/// pseudo-random (but different) shared secret rather than an error.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] if `secret_key` is not 64
/// bytes. Returns [`CryptoError::DecapsulationFailed`] if `ciphertext`
/// has the wrong length.
pub fn decapsulate_kem(secret_key: &[u8], ciphertext: &[u8]) -> Result<Bytes, CryptoError> {
    if secret_key.len() != KEM_SEED_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEM_SEED_LEN,
            got: secret_key.len(),
        });
    }
    let seed: ml_kem::Seed = secret_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEM_SEED_LEN,
            got: secret_key.len(),
        })?;
    let dk = DecapsulationKey1024::from_seed(seed);
    let ss = dk
        .decapsulate_slice(ciphertext)
        .map_err(|_| CryptoError::DecapsulationFailed {
            reason: format!("ciphertext length {} is invalid", ciphertext.len()),
        })?;
    Ok(Bytes::copy_from_slice(ss.as_ref() as &[u8]))
}

// ─── ML-DSA-87 (NIST FIPS 204) ───────────────────────────────────────────────

/// Generate an ML-DSA-87 key pair using the provided CSPRNG.
///
/// The returned [`KeyPair`] stores the 32-byte seed as `secret_key` and
/// the 2592-byte verifying key as `public_key`.
///
/// # Errors
/// This function currently always succeeds; the `Result` is kept for API
/// uniformity with [`generate_kem_keypair`].
pub fn generate_dsa_keypair(rng: &mut impl CryptoRng) -> Result<KeyPair, CryptoError> {
    let signing_key = MlDsa87::key_gen(rng);
    let mut seed = signing_key.to_seed();
    let vk_encoded: EncodedVerifyingKey<MlDsa87> = signing_key.verifying_key().encode();
    let public_key = (vk_encoded.as_ref() as &[u8]).to_vec();
    let secret_key = (seed.as_ref() as &[u8]).to_vec();
    seed.zeroize();
    Ok(KeyPair {
        public_key,
        secret_key,
    })
}

/// Sign `message` with the ML-DSA-87 secret key (32-byte seed).
///
/// Signing is deterministic — no per-call randomness required.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] if `secret_key` is not 32
/// bytes. Returns [`CryptoError::SigningFailed`] if the deterministic
/// signing operation fails.
pub fn sign_dsa(secret_key: &[u8], message: &[u8]) -> Result<Signature, CryptoError> {
    if secret_key.len() != DSA_SEED_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: DSA_SEED_LEN,
            got: secret_key.len(),
        });
    }
    let mut seed_arr: ml_dsa::B32 =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: DSA_SEED_LEN,
                got: secret_key.len(),
            })?;
    let signing_key = MlDsa87::from_seed(&seed_arr);
    seed_arr.zeroize();
    let ml_sig = signing_key
        .signing_key()
        .sign_deterministic(message, b"")
        .map_err(|e| CryptoError::SigningFailed {
            reason: e.to_string(),
        })?;
    let encoded: EncodedSignature<MlDsa87> = ml_sig.encode();
    Ok(Signature(Bytes::copy_from_slice(encoded.as_ref())))
}

/// Verify that `sig` is a valid ML-DSA-87 signature over `message` by
/// `public_key`.
///
/// Returns `Ok(true)` for a valid signature, `Ok(false)` for an invalid one.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] if `public_key` is not 2592
/// bytes. Returns [`CryptoError::VerificationFailed`] if the signature
/// bytes are malformed.
pub fn verify_dsa(public_key: &[u8], message: &[u8], sig: &Signature) -> Result<bool, CryptoError> {
    if public_key.len() != DSA_VK_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: DSA_VK_LEN,
            got: public_key.len(),
        });
    }
    let enc_vk: EncodedVerifyingKey<MlDsa87> =
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: DSA_VK_LEN,
                got: public_key.len(),
            })?;
    let vk = VerifyingKey::<MlDsa87>::decode(&enc_vk);

    let enc_sig: EncodedSignature<MlDsa87> =
        sig.0
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::VerificationFailed {
                reason: "invalid signature length".into(),
            })?;
    let ml_sig = ml_dsa::Signature::<MlDsa87>::decode(&enc_sig).ok_or_else(|| {
        CryptoError::VerificationFailed {
            reason: "malformed signature bytes".into(),
        }
    })?;

    Ok(vk.verify_with_context(message, b"", &ml_sig))
}

// ─── AES-256-GCM Symmetric Encryption ────────────────────────────────────────

/// Encrypt `plaintext` with AES-256-GCM using `key` and `nonce`.
///
/// Returns the ciphertext with authentication tag appended.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] if `key` is not 32 bytes,
/// [`CryptoError::InvalidNonceLength`] if `nonce` is not 12 bytes, or
/// [`CryptoError::EncryptionFailed`] if encryption fails.
pub fn encrypt_aes_gcm(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Bytes, CryptoError> {
    if key.len() != AES_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LEN,
            got: key.len(),
        });
    }
    if nonce.len() != AES_NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength {
            expected: AES_NONCE_LEN,
            got: nonce.len(),
        });
    }

    let aes_key = AesKey::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let aes_nonce = Nonce::from_slice(nonce);

    let ciphertext =
        cipher
            .encrypt(aes_nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed {
                reason: e.to_string(),
            })?;

    Ok(Bytes::from(ciphertext))
}

/// Decrypt and authenticate `ciphertext` with AES-256-GCM using `key` and `nonce`.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] if `key` is not 32 bytes,
/// [`CryptoError::InvalidNonceLength`] if `nonce` is not 12 bytes, or
/// [`CryptoError::DecryptionFailed`] if decryption or authentication fails.
pub fn decrypt_aes_gcm(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Bytes, CryptoError> {
    if key.len() != AES_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LEN,
            got: key.len(),
        });
    }
    if nonce.len() != AES_NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength {
            expected: AES_NONCE_LEN,
            got: nonce.len(),
        });
    }

    let aes_key = AesKey::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let aes_nonce = Nonce::from_slice(nonce);

    let plaintext =
        cipher
            .decrypt(aes_nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed {
                reason: e.to_string(),
            })?;

    Ok(Bytes::from(plaintext))
}

// ─── Argon2id Key Derivation ─────────────────────────────────────────────────

/// Derive a key from `password` and `salt` using Argon2id.
///
/// Uses Argon2id with `time_cost=3`, `mem_cost=65536` KiB (64 MiB), `parallelism=4`.
///
/// # Errors
/// Returns [`CryptoError::KdfFailed`] if key derivation fails or if
/// `output_len` is invalid.
pub fn derive_key(password: &[u8], salt: &[u8], output_len: usize) -> Result<Bytes, CryptoError> {
    if salt.len() != ARGON2_SALT_LEN {
        return Err(CryptoError::KdfFailed {
            reason: format!("salt must be {} bytes, got {}", ARGON2_SALT_LEN, salt.len()),
        });
    }

    // Argon2id parameters: time_cost=3, mem_cost=65536 KiB, parallelism=4
    let params =
        Params::new(65536, 3, 4, Some(output_len)).map_err(|e| CryptoError::KdfFailed {
            reason: e.to_string(),
        })?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    // Create a SaltString from the provided salt
    let salt_str = SaltString::encode_b64(salt).map_err(|e| CryptoError::KdfFailed {
        reason: e.to_string(),
    })?;

    let hash = argon2
        .hash_password(password, &salt_str)
        .map_err(|e| CryptoError::KdfFailed {
            reason: e.to_string(),
        })?;

    // Extract the derived key from the hash
    let hash_output = hash.hash.ok_or_else(|| CryptoError::KdfFailed {
        reason: "no hash output".into(),
    })?;

    Ok(Bytes::copy_from_slice(hash_output.as_bytes()))
}

// ─── Full Encryption Pipeline ────────────────────────────────────────────────

/// Encrypt a payload using the full hybrid cryptosystem pipeline.
///
/// Pipeline: ML-KEM-1024 key encapsulation → derive AES-256-GCM key from
/// shared secret → encrypt payload → sign (KEM ciphertext || AES ciphertext)
/// with ML-DSA-87.
///
/// Output format (all length-prefixed as u32 big-endian):
/// ```text
/// [kem_ct_len][kem_ct][nonce][sym_ct_len][sym_ct][sig_len][sig]
/// ```
///
/// # Errors
/// Returns [`CryptoError`] variants for any cryptographic operation failure.
pub fn encrypt_payload(
    kem_public_key: &[u8],
    dsa_secret_key: &[u8],
    payload: &Payload,
    rng: &mut impl CryptoRng,
) -> Result<Bytes, CryptoError> {
    // 1. KEM encapsulation
    let (kem_ct, shared_secret) = encapsulate_kem(kem_public_key, rng)?;

    // 2. Derive AES key from shared secret
    let mut salt = vec![0u8; ARGON2_SALT_LEN];
    rng.fill_bytes(&mut salt);
    let aes_key_bytes = derive_key(shared_secret.as_ref(), &salt, AES_KEY_LEN)?;

    // 3. Generate nonce
    let mut nonce = vec![0u8; AES_NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    // 4. Encrypt payload
    let sym_ct = encrypt_aes_gcm(&aes_key_bytes, &nonce, payload.as_bytes())?;

    // 5. Sign (kem_ct || salt || nonce || sym_ct)
    let mut message_to_sign = BytesMut::new();
    message_to_sign.put(kem_ct.as_ref());
    message_to_sign.put_slice(&salt);
    message_to_sign.put_slice(&nonce);
    message_to_sign.put(sym_ct.as_ref());

    let signature = sign_dsa(dsa_secret_key, &message_to_sign)?;

    // 6. Build final output: [kem_ct_len][kem_ct][salt][nonce][sym_ct_len][sym_ct][sig_len][sig]
    let mut output = BytesMut::new();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ML-KEM-1024 ciphertext is 1568 bytes"
    )]
    output.put_u32(kem_ct.len() as u32);
    output.put(kem_ct);
    output.put_slice(&salt);
    output.put_slice(&nonce);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "payload sizes are bounded by protocol"
    )]
    output.put_u32(sym_ct.len() as u32);
    output.put(sym_ct);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ML-DSA-87 signature is 4595 bytes"
    )]
    output.put_u32(signature.0.len() as u32);
    output.put(signature.0);

    Ok(output.freeze())
}

/// Decrypt a payload using the full hybrid cryptosystem pipeline.
///
/// Reverses [`encrypt_payload`]: verify signature → KEM decapsulation →
/// derive AES-256-GCM key → decrypt payload.
///
/// # Errors
/// Returns [`CryptoError`] variants for any cryptographic operation failure,
/// including signature verification failure.
pub fn decrypt_payload(
    kem_secret_key: &[u8],
    dsa_public_key: &[u8],
    encrypted: &[u8],
) -> Result<Payload, CryptoError> {
    let mut cursor = encrypted;
    let truncated = |field: &str| CryptoError::DecryptionFailed {
        reason: format!("truncated {field}"),
    };

    // 1. Parse KEM ciphertext
    let kem_ct_len = {
        let b = cursor.get(..4).ok_or_else(|| truncated("kem_ct_len"))?;
        let arr = <[u8; 4]>::try_from(b).map_err(|_| truncated("kem_ct_len"))?;
        cursor = cursor.get(4..).ok_or_else(|| truncated("kem_ct_len"))?;
        u32::from_be_bytes(arr) as usize
    };
    let kem_ct = cursor
        .get(..kem_ct_len)
        .ok_or_else(|| truncated("kem_ct"))?;
    cursor = cursor
        .get(kem_ct_len..)
        .ok_or_else(|| truncated("kem_ct"))?;

    // 2. Parse salt
    let salt = cursor
        .get(..ARGON2_SALT_LEN)
        .ok_or_else(|| truncated("salt"))?;
    cursor = cursor
        .get(ARGON2_SALT_LEN..)
        .ok_or_else(|| truncated("salt"))?;

    // 3. Parse nonce
    let nonce = cursor
        .get(..AES_NONCE_LEN)
        .ok_or_else(|| truncated("nonce"))?;
    cursor = cursor
        .get(AES_NONCE_LEN..)
        .ok_or_else(|| truncated("nonce"))?;

    // 4. Parse symmetric ciphertext
    let sym_ct_len = {
        let b = cursor.get(..4).ok_or_else(|| truncated("sym_ct_len"))?;
        let arr = <[u8; 4]>::try_from(b).map_err(|_| truncated("sym_ct_len"))?;
        cursor = cursor.get(4..).ok_or_else(|| truncated("sym_ct_len"))?;
        u32::from_be_bytes(arr) as usize
    };
    let sym_ct = cursor
        .get(..sym_ct_len)
        .ok_or_else(|| truncated("sym_ct"))?;
    cursor = cursor
        .get(sym_ct_len..)
        .ok_or_else(|| truncated("sym_ct"))?;

    // 5. Parse signature
    let sig_len = {
        let b = cursor.get(..4).ok_or_else(|| truncated("sig_len"))?;
        let arr = <[u8; 4]>::try_from(b).map_err(|_| truncated("sig_len"))?;
        cursor = cursor.get(4..).ok_or_else(|| truncated("sig_len"))?;
        u32::from_be_bytes(arr) as usize
    };
    let sig_bytes = cursor.get(..sig_len).ok_or_else(|| truncated("sig"))?;
    let signature = Signature(Bytes::copy_from_slice(sig_bytes));

    // 6. Verify signature over (kem_ct || salt || nonce || sym_ct)
    let mut message_to_verify = BytesMut::new();
    message_to_verify.put_slice(kem_ct);
    message_to_verify.put_slice(salt);
    message_to_verify.put_slice(nonce);
    message_to_verify.put_slice(sym_ct);

    let sig_valid = verify_dsa(dsa_public_key, &message_to_verify, &signature)?;
    if !sig_valid {
        return Err(CryptoError::DecryptionFailed {
            reason: "signature verification failed".into(),
        });
    }

    // 7. KEM decapsulation
    let shared_secret = decapsulate_kem(kem_secret_key, kem_ct)?;

    // 8. Derive AES key from shared secret
    let aes_key_bytes = derive_key(shared_secret.as_ref(), salt, AES_KEY_LEN)?;

    // 9. Decrypt payload
    let plaintext = decrypt_aes_gcm(&aes_key_bytes, nonce, sym_ct)?;

    Ok(Payload::from_bytes(plaintext.to_vec()))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use subtle::ConstantTimeEq;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_rng(&mut rand::rng())
    }

    // ─── ML-KEM ───────────────────────────────────────────────────────────────

    /// KEM round-trip: shared secrets from encapsulate and decapsulate must match.
    #[test]
    fn test_kem_roundtrip() -> TestResult {
        let kp = generate_kem_keypair(&mut rng())?;
        let (ct, ss_send) = encapsulate_kem(&kp.public_key, &mut rng())?;
        let ss_recv = decapsulate_kem(&kp.secret_key, &ct)?;

        let eq = ss_send.as_ref().ct_eq(ss_recv.as_ref()).unwrap_u8();
        assert_eq!(eq, 1u8, "shared secrets must match");
        Ok(())
    }

    /// Invalid ciphertext must not produce the correct shared secret
    /// (ML-KEM uses implicit rejection — not an error, but a different key).
    #[test]
    fn test_kem_wrong_ciphertext_differs() -> TestResult {
        let kp = generate_kem_keypair(&mut rng())?;
        let (ct, ss_good) = encapsulate_kem(&kp.public_key, &mut rng())?;
        // Flip first byte to corrupt ciphertext
        let mut ct_vec = ct.to_vec();
        let first = ct_vec.first_mut().ok_or("empty ciphertext")?;
        *first ^= 0xFF;
        let ss_bad = decapsulate_kem(&kp.secret_key, &ct_vec)?;

        let eq = ss_good.as_ref().ct_eq(ss_bad.as_ref()).unwrap_u8();
        assert_eq!(
            eq, 0u8,
            "corrupted ciphertext must yield a different shared secret"
        );
        Ok(())
    }

    /// Wrong public key length must return `InvalidKeyLength`.
    #[test]
    fn test_kem_bad_pubkey_length() {
        let result = encapsulate_kem(&[0u8; 42], &mut rng());
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    /// Wrong secret key length must return `InvalidKeyLength`.
    #[test]
    fn test_kem_bad_seckey_length() {
        let ct = Bytes::from(vec![0u8; 1568]);
        let result = decapsulate_kem(&[0u8; 42], &ct);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    /// Key pair byte sizes must match ML-KEM-1024 FIPS 203 specification.
    #[test]
    fn test_kem_keypair_sizes() -> TestResult {
        let kp = generate_kem_keypair(&mut rng())?;
        assert_eq!(
            kp.secret_key.len(),
            KEM_SEED_LEN,
            "KEM seed must be 64 bytes"
        );
        assert_eq!(
            kp.public_key.len(),
            KEM_EK_LEN,
            "KEM enc key must be 1568 bytes"
        );
        Ok(())
    }

    // ─── ML-DSA ───────────────────────────────────────────────────────────────

    /// DSA round-trip: sign then verify must return `true`.
    #[test]
    fn test_dsa_roundtrip() -> TestResult {
        let kp = generate_dsa_keypair(&mut rng())?;
        let msg = b"the quick brown fox jumps over the lazy dog";
        let sig = sign_dsa(&kp.secret_key, msg)?;
        let ok = verify_dsa(&kp.public_key, msg, &sig)?;
        assert!(ok, "valid signature must verify");
        Ok(())
    }

    /// Tampered signature must not verify.
    #[test]
    fn test_dsa_tamper() -> TestResult {
        let kp = generate_dsa_keypair(&mut rng())?;
        let msg = b"the quick brown fox jumps over the lazy dog";
        let sig = sign_dsa(&kp.secret_key, msg)?;
        let mut sig_bytes = sig.0.to_vec();
        let first = sig_bytes.first_mut().ok_or("empty signature")?;
        *first ^= 0xFF;
        let tampered_sig = Signature(Bytes::from(sig_bytes));
        let result = verify_dsa(&kp.public_key, msg, &tampered_sig);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "tampered signature must not verify"
        );
        Ok(())
    }

    /// Signature under a different public key must not verify.
    #[test]
    fn test_dsa_wrong_key() -> TestResult {
        let kp1 = generate_dsa_keypair(&mut rng())?;
        let kp2 = generate_dsa_keypair(&mut rng())?;
        let msg = b"the quick brown fox jumps over the lazy dog";
        let sig = sign_dsa(&kp1.secret_key, msg)?;
        let result = verify_dsa(&kp2.public_key, msg, &sig);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "sig must not verify under a different key"
        );
        Ok(())
    }

    /// Key pair byte sizes must match ML-DSA-87 FIPS 204 specification.
    #[test]
    fn test_dsa_keypair_sizes() -> TestResult {
        let kp = generate_dsa_keypair(&mut rng())?;
        assert_eq!(
            kp.secret_key.len(),
            DSA_SEED_LEN,
            "DSA seed must be 32 bytes"
        );
        assert_eq!(
            kp.public_key.len(),
            DSA_VK_LEN,
            "DSA verifying key must be 2592 bytes"
        );
        Ok(())
    }

    // ─── AES-256-GCM ──────────────────────────────────────────────────────────

    /// AES-256-GCM round-trip: encrypt then decrypt yields original plaintext.
    #[test]
    fn test_aes_roundtrip() -> TestResult {
        let key = vec![0u8; AES_KEY_LEN];
        let nonce = vec![1u8; AES_NONCE_LEN];
        let plaintext = b"the quick brown fox";
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext)?;
        let recovered = decrypt_aes_gcm(&key, &nonce, &ciphertext)?;
        assert_eq!(recovered.as_ref(), plaintext);
        Ok(())
    }

    /// Tampered ciphertext must fail authentication.
    #[test]
    fn test_aes_tamper() -> TestResult {
        let key = vec![0u8; AES_KEY_LEN];
        let nonce = vec![1u8; AES_NONCE_LEN];
        let plaintext = b"the quick brown fox";
        let mut ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext)?.to_vec();
        let first = ciphertext.first_mut().ok_or("empty ciphertext")?;
        *first ^= 0xFF;
        let result = decrypt_aes_gcm(&key, &nonce, &ciphertext);
        assert!(result.is_err(), "tampered ciphertext must fail to decrypt");
        Ok(())
    }

    /// Wrong key length must return `InvalidKeyLength`.
    #[test]
    fn test_aes_bad_key_length() {
        let key = vec![0u8; 16]; // Wrong length
        let nonce = vec![1u8; AES_NONCE_LEN];
        let plaintext = b"test";
        let result = encrypt_aes_gcm(&key, &nonce, plaintext);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    /// Wrong nonce length must return `InvalidNonceLength`.
    #[test]
    fn test_aes_bad_nonce_length() {
        let key = vec![0u8; AES_KEY_LEN];
        let nonce = vec![1u8; 8]; // Wrong length
        let plaintext = b"test";
        let result = encrypt_aes_gcm(&key, &nonce, plaintext);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength { .. })
        ));
    }

    // ─── Argon2id KDF ─────────────────────────────────────────────────────────

    /// Argon2id must produce deterministic output for same password + salt.
    #[test]
    fn test_kdf_deterministic() -> TestResult {
        let password = b"password123";
        let salt = vec![0u8; ARGON2_SALT_LEN];
        let key1 = derive_key(password, &salt, AES_KEY_LEN)?;
        let key2 = derive_key(password, &salt, AES_KEY_LEN)?;
        assert_eq!(key1.as_ref(), key2.as_ref(), "KDF must be deterministic");
        Ok(())
    }

    /// Argon2id must produce different output for different passwords.
    #[test]
    fn test_kdf_different_passwords() -> TestResult {
        let salt = vec![0u8; ARGON2_SALT_LEN];
        let key1 = derive_key(b"password1", &salt, AES_KEY_LEN)?;
        let key2 = derive_key(b"password2", &salt, AES_KEY_LEN)?;
        assert_ne!(
            key1.as_ref(),
            key2.as_ref(),
            "different passwords must yield different keys"
        );
        Ok(())
    }

    /// Argon2id must produce different output for different salts.
    #[test]
    fn test_kdf_different_salts() -> TestResult {
        let password = b"password123";
        let salt1 = vec![0u8; ARGON2_SALT_LEN];
        let salt2 = vec![1u8; ARGON2_SALT_LEN];
        let key1 = derive_key(password, &salt1, AES_KEY_LEN)?;
        let key2 = derive_key(password, &salt2, AES_KEY_LEN)?;
        assert_ne!(
            key1.as_ref(),
            key2.as_ref(),
            "different salts must yield different keys"
        );
        Ok(())
    }

    // ─── Full Pipeline ────────────────────────────────────────────────────────

    /// Full pipeline round-trip: encrypt then decrypt yields original payload.
    #[test]
    fn test_pipeline_roundtrip() -> TestResult {
        let kem_kp = generate_kem_keypair(&mut rng())?;
        let dsa_kp = generate_dsa_keypair(&mut rng())?;
        let payload = crate::domain::types::Payload::from_bytes(b"secret message".to_vec());

        let encrypted =
            encrypt_payload(&kem_kp.public_key, &dsa_kp.secret_key, &payload, &mut rng())?;

        let recovered = decrypt_payload(&kem_kp.secret_key, &dsa_kp.public_key, &encrypted)?;

        assert_eq!(recovered.as_bytes(), payload.as_bytes());
        Ok(())
    }

    /// Full pipeline with tampered ciphertext must fail signature verification.
    #[test]
    fn test_pipeline_tamper() -> TestResult {
        let kem_kp = generate_kem_keypair(&mut rng())?;
        let dsa_kp = generate_dsa_keypair(&mut rng())?;
        let payload = crate::domain::types::Payload::from_bytes(b"secret message".to_vec());

        let mut encrypted =
            encrypt_payload(&kem_kp.public_key, &dsa_kp.secret_key, &payload, &mut rng())?.to_vec();

        // Tamper with a byte in the middle
        let mid = encrypted.len() / 2;
        let byte = encrypted.get_mut(mid).ok_or("empty encrypted data")?;
        *byte ^= 0xFF;

        let result = decrypt_payload(&kem_kp.secret_key, &dsa_kp.public_key, &encrypted);
        assert!(result.is_err(), "tampered payload must fail to decrypt");
        Ok(())
    }

    /// Full pipeline with wrong DSA key must fail signature verification.
    #[test]
    fn test_pipeline_wrong_dsa_key() -> TestResult {
        let kem_kp = generate_kem_keypair(&mut rng())?;
        let dsa_kp1 = generate_dsa_keypair(&mut rng())?;
        let dsa_kp2 = generate_dsa_keypair(&mut rng())?;
        let payload = crate::domain::types::Payload::from_bytes(b"secret message".to_vec());

        let encrypted = encrypt_payload(
            &kem_kp.public_key,
            &dsa_kp1.secret_key,
            &payload,
            &mut rng(),
        )?;

        let result = decrypt_payload(&kem_kp.secret_key, &dsa_kp2.public_key, &encrypted);
        assert!(result.is_err(), "wrong DSA key must fail verification");
        Ok(())
    }

    // ─── Additional edge-case coverage ────────────────────────────────────

    /// KDF with wrong salt length must return `KdfFailed`.
    #[test]
    fn test_kdf_bad_salt_length() {
        let result = derive_key(b"password", &[0u8; 16], AES_KEY_LEN);
        assert!(matches!(result, Err(CryptoError::KdfFailed { .. })));
    }

    /// DSA sign with wrong secret key length must return `InvalidKeyLength`.
    #[test]
    fn test_dsa_sign_bad_key_length() {
        let result = sign_dsa(&[0u8; 16], b"message");
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    /// DSA verify with wrong public key length must return `InvalidKeyLength`.
    #[test]
    fn test_dsa_verify_bad_pubkey_length() {
        let sig = Signature(Bytes::from(vec![0u8; 64]));
        let result = verify_dsa(&[0u8; 16], b"message", &sig);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    /// KEM decapsulate with invalid ciphertext length must return `DecapsulationFailed`.
    #[test]
    fn test_kem_bad_ciphertext_length() -> TestResult {
        let kp = generate_kem_keypair(&mut rng())?;
        let result = decapsulate_kem(&kp.secret_key, &[0u8; 42]);
        assert!(matches!(
            result,
            Err(CryptoError::DecapsulationFailed { .. })
        ));
        Ok(())
    }

    /// AES decrypt with bad key length must return `InvalidKeyLength`.
    #[test]
    fn test_aes_decrypt_bad_key_length() {
        let result = decrypt_aes_gcm(&[0u8; 16], &[0u8; AES_NONCE_LEN], &[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    /// AES decrypt with bad nonce length must return `InvalidNonceLength`.
    #[test]
    fn test_aes_decrypt_bad_nonce_length() {
        let result = decrypt_aes_gcm(&[0u8; AES_KEY_LEN], &[0u8; 8], &[0u8; 32]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength { .. })
        ));
    }

    /// Decrypt pipeline with truncated input must return `DecryptionFailed`.
    #[test]
    fn test_decrypt_pipeline_truncated_empty() {
        let result = decrypt_payload(&[0u8; KEM_SEED_LEN], &[0u8; DSA_VK_LEN], &[]);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed { .. })));
    }

    /// Decrypt pipeline with truncated input after `kem_ct_len` must return `DecryptionFailed`.
    #[test]
    fn test_decrypt_pipeline_truncated_after_header() {
        let result = decrypt_payload(&[0u8; KEM_SEED_LEN], &[0u8; DSA_VK_LEN], &[0u8; 8]);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed { .. })));
    }

    /// DSA verify with malformed signature (wrong length) must return `VerificationFailed`.
    #[test]
    fn test_dsa_verify_bad_sig_length() -> TestResult {
        let kp = generate_dsa_keypair(&mut rng())?;
        let bad_sig = Signature(Bytes::from(vec![0u8; 10])); // Too short
        let result = verify_dsa(&kp.public_key, b"message", &bad_sig);
        assert!(
            matches!(result, Err(CryptoError::VerificationFailed { .. })),
            "expected VerificationFailed, got {result:?}"
        );
        Ok(())
    }

    /// Empty plaintext encrypts and decrypts correctly.
    #[test]
    fn test_aes_empty_plaintext() -> TestResult {
        let key = vec![0u8; AES_KEY_LEN];
        let nonce = vec![1u8; AES_NONCE_LEN];
        let ciphertext = encrypt_aes_gcm(&key, &nonce, &[])?;
        let recovered = decrypt_aes_gcm(&key, &nonce, &ciphertext)?;
        assert!(recovered.is_empty());
        Ok(())
    }

    /// Full pipeline with empty payload.
    #[test]
    fn test_pipeline_empty_payload() -> TestResult {
        let kem_kp = generate_kem_keypair(&mut rng())?;
        let dsa_kp = generate_dsa_keypair(&mut rng())?;
        let payload = crate::domain::types::Payload::from_bytes(Vec::new());

        let encrypted =
            encrypt_payload(&kem_kp.public_key, &dsa_kp.secret_key, &payload, &mut rng())?;
        let recovered = decrypt_payload(&kem_kp.secret_key, &dsa_kp.public_key, &encrypted)?;
        assert!(recovered.is_empty());
        Ok(())
    }
}
