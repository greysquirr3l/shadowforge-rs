//! ML-KEM-1024, ML-DSA-87, Argon2id, AES-256-GCM, and secure zeroing.
//!
//! All functions are pure — no I/O, no file system, no network. Each
//! function that needs randomness accepts a CSPRNG as a parameter so it
//! can be exercised with a seeded RNG in tests.

use bytes::Bytes;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa87, VerifyingKey, signature::Keypair};
use ml_kem::{Decapsulate, DecapsulationKey1024, Encapsulate as _, EncapsulationKey1024, Kem as _, Key, KeyExport as _, MlKem1024};
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::domain::errors::CryptoError;
use crate::domain::types::{KeyPair, Signature};

/// Expected byte-length of an ML-KEM-1024 seed (secret key stored form).
const KEM_SEED_LEN: usize = 64;
/// Expected byte-length of an ML-KEM-1024 encapsulation (public) key.
const KEM_EK_LEN: usize = 1568;
/// Expected byte-length of an ML-DSA-87 seed (secret key stored form).
const DSA_SEED_LEN: usize = 32;
/// Expected byte-length of an ML-DSA-87 verifying (public) key.
const DSA_VK_LEN: usize = 2592;

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
    let seed = dk
        .to_seed()
        .ok_or_else(|| CryptoError::KeyGenFailed { reason: "freshly generated key has no seed".into() })?;
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
        return Err(CryptoError::InvalidKeyLength { expected: KEM_EK_LEN, got: public_key.len() });
    }
    let key_arr: Key<EncapsulationKey1024> = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength { expected: KEM_EK_LEN, got: public_key.len() })?;
    let ek = EncapsulationKey1024::new(&key_arr)
        .map_err(|_| CryptoError::EncapsulationFailed { reason: "invalid encapsulation key".into() })?;
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
        return Err(CryptoError::InvalidKeyLength { expected: KEM_SEED_LEN, got: secret_key.len() });
    }
    let seed: ml_kem::Seed = secret_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength { expected: KEM_SEED_LEN, got: secret_key.len() })?;
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
    Ok(KeyPair { public_key, secret_key })
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
        return Err(CryptoError::InvalidKeyLength { expected: DSA_SEED_LEN, got: secret_key.len() });
    }
    let mut seed_arr: ml_dsa::B32 = secret_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength { expected: DSA_SEED_LEN, got: secret_key.len() })?;
    let signing_key = MlDsa87::from_seed(&seed_arr);
    seed_arr.zeroize();
    let ml_sig = signing_key
        .signing_key()
        .sign_deterministic(message, b"")
        .map_err(|e| CryptoError::SigningFailed { reason: e.to_string() })?;
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
pub fn verify_dsa(
    public_key: &[u8],
    message: &[u8],
    sig: &Signature,
) -> Result<bool, CryptoError> {
    if public_key.len() != DSA_VK_LEN {
        return Err(CryptoError::InvalidKeyLength { expected: DSA_VK_LEN, got: public_key.len() });
    }
    let enc_vk: EncodedVerifyingKey<MlDsa87> = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength { expected: DSA_VK_LEN, got: public_key.len() })?;
    let vk = VerifyingKey::<MlDsa87>::decode(&enc_vk);

    let enc_sig: EncodedSignature<MlDsa87> = sig
        .0
        .as_ref()
        .try_into()
        .map_err(|_| CryptoError::VerificationFailed { reason: "invalid signature length".into() })?;
    let ml_sig = ml_dsa::Signature::<MlDsa87>::decode(&enc_sig)
        .ok_or_else(|| CryptoError::VerificationFailed { reason: "malformed signature bytes".into() })?;

    Ok(vk.verify_with_context(message, b"", &ml_sig))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use subtle::ConstantTimeEq;

    use super::*;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_rng(&mut rand::rng())
    }

    // ─── ML-KEM ───────────────────────────────────────────────────────────────

    /// KEM round-trip: shared secrets from encapsulate and decapsulate must match.
    #[test]
    fn test_kem_roundtrip() {
        let kp = generate_kem_keypair(&mut rng()).expect("keygen");
        let (ct, ss_send) = encapsulate_kem(&kp.public_key, &mut rng()).expect("enc");
        let ss_recv = decapsulate_kem(&kp.secret_key, &ct).expect("dec");

        let eq = ss_send.as_ref().ct_eq(ss_recv.as_ref()).unwrap_u8();
        assert_eq!(eq, 1u8, "shared secrets must match");
    }

    /// Invalid ciphertext must not produce the correct shared secret
    /// (ML-KEM uses implicit rejection — not an error, but a different key).
    #[test]
    fn test_kem_wrong_ciphertext_differs() {
        let kp = generate_kem_keypair(&mut rng()).expect("keygen");
        let (ct, ss_good) = encapsulate_kem(&kp.public_key, &mut rng()).expect("enc");
        // Flip first byte to corrupt ciphertext
        let mut ct_vec = ct.to_vec();
        ct_vec[0] ^= 0xFF;
        let ss_bad = decapsulate_kem(&kp.secret_key, &ct_vec).expect("dec");

        let eq = ss_good.as_ref().ct_eq(ss_bad.as_ref()).unwrap_u8();
        assert_eq!(eq, 0u8, "corrupted ciphertext must yield a different shared secret");
    }

    /// Wrong public key length must return `InvalidKeyLength`.
    #[test]
    fn test_kem_bad_pubkey_length() {
        let err = encapsulate_kem(&[0u8; 42], &mut rng()).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKeyLength { .. }));
    }

    /// Wrong secret key length must return `InvalidKeyLength`.
    #[test]
    fn test_kem_bad_seckey_length() {
        let ct = Bytes::from(vec![0u8; 1568]);
        let err = decapsulate_kem(&[0u8; 42], &ct).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKeyLength { .. }));
    }

    /// Key pair byte sizes must match ML-KEM-1024 FIPS 203 specification.
    #[test]
    fn test_kem_keypair_sizes() {
        let kp = generate_kem_keypair(&mut rng()).expect("keygen");
        assert_eq!(kp.secret_key.len(), KEM_SEED_LEN, "KEM seed must be 64 bytes");
        assert_eq!(kp.public_key.len(), KEM_EK_LEN, "KEM enc key must be 1568 bytes");
    }

    // ─── ML-DSA ───────────────────────────────────────────────────────────────

    /// DSA round-trip: sign then verify must return `true`.
    #[test]
    fn test_dsa_roundtrip() {
        let kp = generate_dsa_keypair(&mut rng()).expect("keygen");
        let msg = b"the quick brown fox jumps over the lazy dog";
        let sig = sign_dsa(&kp.secret_key, msg).expect("sign");
        let ok = verify_dsa(&kp.public_key, msg, &sig).expect("verify");
        assert!(ok, "valid signature must verify");
    }

    /// Tampered signature must not verify.
    #[test]
    fn test_dsa_tamper() {
        let kp = generate_dsa_keypair(&mut rng()).expect("keygen");
        let msg = b"the quick brown fox jumps over the lazy dog";
        let sig = sign_dsa(&kp.secret_key, msg).expect("sign");
        let mut sig_bytes = sig.0.to_vec();
        sig_bytes[0] ^= 0xFF;
        let tampered_sig = Signature(Bytes::from(sig_bytes));
        let result = verify_dsa(&kp.public_key, msg, &tampered_sig);
        match result {
            Ok(false) | Err(_) => {}
            Ok(true) => panic!("tampered signature must not verify"),
        }
    }

    /// Signature under a different public key must not verify.
    #[test]
    fn test_dsa_wrong_key() {
        let kp1 = generate_dsa_keypair(&mut rng()).expect("keygen 1");
        let kp2 = generate_dsa_keypair(&mut rng()).expect("keygen 2");
        let msg = b"the quick brown fox jumps over the lazy dog";
        let sig = sign_dsa(&kp1.secret_key, msg).expect("sign");
        let result = verify_dsa(&kp2.public_key, msg, &sig);
        match result {
            Ok(false) | Err(_) => {}
            Ok(true) => panic!("sig must not verify under a different key"),
        }
    }

    /// Key pair byte sizes must match ML-DSA-87 FIPS 204 specification.
    #[test]
    fn test_dsa_keypair_sizes() {
        let kp = generate_dsa_keypair(&mut rng()).expect("keygen");
        assert_eq!(kp.secret_key.len(), DSA_SEED_LEN, "DSA seed must be 32 bytes");
        assert_eq!(kp.public_key.len(), DSA_VK_LEN, "DSA verifying key must be 2592 bytes");
    }
}
