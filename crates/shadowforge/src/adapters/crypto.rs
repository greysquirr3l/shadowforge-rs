//! Cryptographic adapters — ML-KEM-1024, ML-DSA-87, and AES-256-GCM.
//!
//! Each struct implements the corresponding port trait from
//! [`crate::domain::ports`] and wires in a `ChaCha20Rng` seeded from the OS
//! entropy source at each call, providing forward secrecy between calls.

use bytes::Bytes;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::domain::crypto::{
    decapsulate_kem, decrypt_aes_gcm, encapsulate_kem, encrypt_aes_gcm, generate_dsa_keypair,
    generate_kem_keypair, sign_dsa, verify_dsa,
};
use crate::domain::errors::CryptoError;
use crate::domain::ports::{Encryptor, Signer, SymmetricCipher};
use crate::domain::types::{KeyPair, Signature};

// ─── Helpers ──────────────────────────────────────────────────────────────────────────────────────

/// Construct a `ChaCha20Rng` freshly seeded from the OS entropy source.
fn fresh_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_rng(&mut rand::rng())
}

// ─── MlKemEncryptor ───────────────────────────────────────────────────────────

/// ML-KEM-1024 key-encapsulation adapter.
///
/// Implements the [`Encryptor`] port using the `ml-kem` crate (NIST FIPS 203).
/// Each call seeds a fresh `ChaCha20Rng` from the OS, ensuring forward
/// secrecy between calls.
#[derive(Debug, Default)]
pub struct MlKemEncryptor;

impl Encryptor for MlKemEncryptor {
    fn generate_keypair(&self) -> Result<KeyPair, CryptoError> {
        generate_kem_keypair(&mut fresh_rng())
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(Bytes, Bytes), CryptoError> {
        encapsulate_kem(public_key, &mut fresh_rng())
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Bytes, CryptoError> {
        decapsulate_kem(secret_key, ciphertext)
    }
}

// ─── MlDsaSigner ─────────────────────────────────────────────────────────────

/// ML-DSA-87 digital signature adapter.
///
/// Implements the [`Signer`] port using the `ml-dsa` crate (NIST FIPS 204).
/// Signing is deterministic (no per-call randomness) for auditability.
#[derive(Debug, Default)]
pub struct MlDsaSigner;

impl Signer for MlDsaSigner {
    fn generate_keypair(&self) -> Result<KeyPair, CryptoError> {
        generate_dsa_keypair(&mut fresh_rng())
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Signature, CryptoError> {
        sign_dsa(secret_key, message)
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, CryptoError> {
        verify_dsa(public_key, message, signature)
    }
}

// ─── Aes256GcmCipher ──────────────────────────────────────────────────────────

/// AES-256-GCM symmetric cipher adapter.
///
/// Implements the [`SymmetricCipher`] port using the `aes-gcm` crate.
#[derive(Debug, Default)]
pub struct Aes256GcmCipher;

impl SymmetricCipher for Aes256GcmCipher {
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Bytes, CryptoError> {
        encrypt_aes_gcm(key, nonce, plaintext)
    }

    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Bytes, CryptoError> {
        decrypt_aes_gcm(key, nonce, ciphertext)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_encryptor_adapter_roundtrip() -> TestResult {
        let enc = MlKemEncryptor;
        let kp = enc.generate_keypair()?;
        let (ct, ss1) = enc.encapsulate(&kp.public_key)?;
        let ss2 = enc.decapsulate(&kp.secret_key, &ct)?;
        assert_eq!(ss1.as_ref(), ss2.as_ref());
        Ok(())
}

    #[test]
    fn test_signer_adapter_roundtrip() -> TestResult {
        let signer = MlDsaSigner;
        let kp = signer.generate_keypair()?;
        let msg = b"test message for adapter";
        let sig = signer.sign(&kp.secret_key, msg)?;
        let ok = signer.verify(&kp.public_key, msg, &sig)?;
        assert!(ok, "valid sig must verify via adapter");
        Ok(())
}

    #[test]
    fn test_signer_adapter_wrong_message() -> TestResult {
        let signer = MlDsaSigner;
        let kp = signer.generate_keypair()?;
        let sig = signer.sign(&kp.secret_key, b"original")?;
        let ok = signer
            .verify(&kp.public_key, b"tampered", &sig)
            ?;
        assert!(!ok, "sig over original must not verify against tampered msg");
        Ok(())
}

    #[test]
    fn test_symmetric_adapter_roundtrip() -> TestResult {
        let cipher = Aes256GcmCipher;
        let key = vec![0u8; 32];
        let nonce = vec![1u8; 12];
        let plaintext = b"test message";
        let ciphertext = cipher.encrypt(&key, &nonce, plaintext)?;
        let recovered = cipher.decrypt(&key, &nonce, &ciphertext)?;
        assert_eq!(recovered.as_ref(), plaintext);
        Ok(())
}

    #[test]
    fn test_symmetric_adapter_tamper() -> TestResult {
        let cipher = Aes256GcmCipher;
        let key = vec![0u8; 32];
        let nonce = vec![1u8; 12];
        let plaintext = b"test message";
        let mut ciphertext = cipher.encrypt(&key, &nonce, plaintext)?.to_vec();
        *ciphertext.get_mut(0).ok_or("out of bounds")? ^= 0xFF;
        let result = cipher.decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err(), "tampered ciphertext must fail to decrypt");
        Ok(())
}
}
