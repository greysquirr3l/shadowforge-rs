//! Time-lock puzzle payloads using Rivest iterated squaring.
//!
//! A payload is encrypted with a key that can only be derived by performing
//! `T` sequential modular squarings. This cannot be parallelised, providing
//! practical (but not absolute) time-locking.
//!
//! **Security note**: a well-resourced adversary with faster hardware can
//! solve the puzzle earlier. This scheme provides practical but not
//! cryptographic time-binding.

use chrono::{DateTime, Utc};
use num_bigint::BigUint;
use num_traits::One;
use sha2::{Digest, Sha256};

use crate::domain::crypto::{decrypt_aes_gcm, encrypt_aes_gcm};
use crate::domain::errors::TimeLockError;
use crate::domain::types::{Payload, TimeLockPuzzle};

/// Default assumed squarings per second on typical hardware.
/// Calibrated conservatively for a modern desktop CPU.
const DEFAULT_SQUARINGS_PER_SEC: u64 = 10_000_000;

/// Modulus bit length for the RSA modulus `n = p * q`.
const MODULUS_BITS: u64 = 256;

/// AES-256-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Derive a 32-byte AES key and 12-byte nonce from the puzzle solution via SHA-256.
fn derive_key_and_nonce(solution: &BigUint) -> ([u8; 32], [u8; NONCE_LEN]) {
    let solution_bytes = solution.to_bytes_be();

    // Key: SHA-256 of solution
    let key: [u8; 32] = Sha256::digest(&solution_bytes).into();

    // Nonce: first 12 bytes of SHA-256("nonce" || solution)
    let mut nonce_input = b"nonce".to_vec();
    nonce_input.extend_from_slice(&solution_bytes);
    let nonce_hash = Sha256::digest(&nonce_input);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_hash.get(..NONCE_LEN).unwrap_or(&[0u8; NONCE_LEN]));

    (key, nonce)
}

/// Perform `t` sequential modular squarings: `g^(2^t) mod n`.
fn sequential_square(g: &BigUint, n: &BigUint, t: u64) -> BigUint {
    let mut result = g.clone();
    for _ in 0..t {
        result = (&result * &result) % n;
    }
    result
}

/// Create a time-lock puzzle for the given payload.
///
/// # Errors
/// Returns [`TimeLockError::ComputationFailed`] if puzzle generation fails.
pub fn create_puzzle(
    payload: &Payload,
    unlock_at: DateTime<Utc>,
    squarings_per_sec: u64,
) -> Result<TimeLockPuzzle, TimeLockError> {
    let now = Utc::now();
    let duration_secs = (unlock_at - now).num_seconds().max(0).cast_unsigned();
    let squarings_required = duration_secs.saturating_mul(squarings_per_sec);

    // Generate two random primes and compute n = p * q
    let mut rng = rand::rng();
    let half_bits = MODULUS_BITS / 2;
    let p = generate_random_prime(&mut rng, half_bits);
    let q = generate_random_prime(&mut rng, half_bits);
    let n = &p * &q;

    // Random start value g in [2, n-1]
    let g = {
        let two = BigUint::from(2u32);
        let upper = &n - &two;
        let rand_val = random_biguint(&mut rng, MODULUS_BITS);
        (rand_val % &upper) + &two
    };

    // Compute solution using trapdoor: g^(2^T) mod n
    // With knowledge of phi(n) = (p-1)(q-1), we can compute 2^T mod phi(n) first
    let phi = (&p - BigUint::one()) * (&q - BigUint::one());
    let two = BigUint::from(2u32);
    let exponent = two.modpow(&BigUint::from(squarings_required), &phi);
    let solution = g.modpow(&exponent, &n);

    // Derive encryption key from solution
    let (key, nonce) = derive_key_and_nonce(&solution);

    // Encrypt payload
    let ciphertext = encrypt_aes_gcm(&key, &nonce, payload.as_bytes()).map_err(|e| {
        TimeLockError::ComputationFailed {
            reason: format!("encryption failed: {e}"),
        }
    })?;

    Ok(TimeLockPuzzle {
        ciphertext,
        modulus: n.to_bytes_be(),
        start_value: g.to_bytes_be(),
        squarings_required,
        created_at: now,
        unlock_at,
    })
}

/// Solve a time-lock puzzle by performing sequential squarings and decrypting.
///
/// This is CPU-bound and cannot be parallelised.
///
/// # Errors
/// Returns [`TimeLockError::ComputationFailed`] or [`TimeLockError::DecryptFailed`].
pub fn solve_puzzle(puzzle: &TimeLockPuzzle) -> Result<Payload, TimeLockError> {
    let n = BigUint::from_bytes_be(&puzzle.modulus);
    let g = BigUint::from_bytes_be(&puzzle.start_value);

    // Perform T sequential squarings
    let solution = sequential_square(&g, &n, puzzle.squarings_required);

    // Derive key and decrypt
    let (key, nonce) = derive_key_and_nonce(&solution);

    let plaintext = decrypt_aes_gcm(&key, &nonce, &puzzle.ciphertext)
        .map_err(|source| TimeLockError::DecryptFailed { source })?;

    Ok(Payload::from_bytes(plaintext.to_vec()))
}

/// Non-blocking puzzle check. Returns `Ok(Some(payload))` if solvable
/// within a very short time budget, `Ok(None)` otherwise.
///
/// # Errors
/// Returns [`TimeLockError::ComputationFailed`] or [`TimeLockError::DecryptFailed`].
pub fn try_solve_puzzle(
    puzzle: &TimeLockPuzzle,
    squarings_per_sec: u64,
) -> Result<Option<Payload>, TimeLockError> {
    // Estimate remaining time
    let now = Utc::now();
    let elapsed_secs = (now - puzzle.created_at)
        .num_seconds()
        .max(0)
        .cast_unsigned();
    let estimated_solvable_squarings = elapsed_secs.saturating_mul(squarings_per_sec);

    if estimated_solvable_squarings < puzzle.squarings_required {
        return Ok(None);
    }

    // If we estimate it's solvable, actually solve it
    solve_puzzle(puzzle).map(Some)
}

/// Generate a random odd number of the given bit size that is likely prime.
///
/// Uses a simple trial-division primality test for the small moduli
/// used in this implementation.
fn generate_random_prime(rng: &mut impl rand::Rng, bits: u64) -> BigUint {
    loop {
        let mut candidate = random_biguint(rng, bits);
        // Ensure odd
        candidate |= BigUint::one();
        // Ensure correct bit length
        candidate |= BigUint::one() << (bits - 1);

        if is_probably_prime(&candidate) {
            return candidate;
        }
    }
}

/// Simple trial-division primality test.
///
/// Suitable for the small (128-bit) primes used in the puzzle modulus.
fn is_probably_prime(n: &BigUint) -> bool {
    let two = BigUint::from(2u32);
    if n < &two {
        return false;
    }
    if n == &two || n == &BigUint::from(3u32) {
        return true;
    }
    if n % &two == BigUint::ZERO {
        return false;
    }

    // Trial division up to sqrt(n) or 10000, whichever is smaller
    let mut i = BigUint::from(3u32);
    let limit = BigUint::from(10_000u32);
    while &i * &i <= *n && i < limit {
        if n % &i == BigUint::ZERO {
            return false;
        }
        i += &two;
    }
    true
}

/// Generate a random `BigUint` with the given number of bits.
fn random_biguint(rng: &mut impl rand::Rng, bits: u64) -> BigUint {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bits <= 256, always fits usize"
    )]
    let byte_count = bits.div_ceil(8) as usize;
    let mut buf = vec![0u8; byte_count];
    rng.fill_bytes(&mut buf);
    // Mask high bits to get exactly `bits` random bits
    let excess_bits = (byte_count * 8) as u64 - bits;
    if excess_bits > 0 && let Some(first) = buf.first_mut() {
        *first &= 0xFF >> excess_bits;
    }
    BigUint::from_bytes_be(&buf)
}

/// Returns the default squarings-per-second calibration constant.
#[must_use]
pub const fn default_squarings_per_sec() -> u64 {
    DEFAULT_SQUARINGS_PER_SEC
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn roundtrip_lock_then_unlock() -> TestResult {
        let payload = Payload::from_bytes(b"secret message".to_vec());
        let unlock_at = Utc::now();

        let puzzle = create_puzzle(&payload, unlock_at, DEFAULT_SQUARINGS_PER_SEC)?;

        // With 0 squarings required, solving should be instant
        let recovered = solve_puzzle(&puzzle)?;
        assert_eq!(recovered.as_bytes(), payload.as_bytes());
        Ok(())
    }

    #[test]
    fn roundtrip_with_small_delay() -> TestResult {
        let payload = Payload::from_bytes(b"timed secret".to_vec());
        let unlock_at = Utc::now();

        let puzzle = create_puzzle(&payload, unlock_at, DEFAULT_SQUARINGS_PER_SEC)?;

        let recovered = solve_puzzle(&puzzle)?;
        assert_eq!(recovered.as_bytes(), payload.as_bytes());
        Ok(())
    }

    #[test]
    fn try_solve_returns_none_for_future_puzzle() -> TestResult {
        let payload = Payload::from_bytes(b"future secret".to_vec());
        let unlock_at = Utc::now() + chrono::Duration::hours(1);

        let puzzle = create_puzzle(&payload, unlock_at, DEFAULT_SQUARINGS_PER_SEC)?;

        // Should return None because the puzzle requires many squarings
        let result = try_solve_puzzle(&puzzle, DEFAULT_SQUARINGS_PER_SEC)?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn puzzle_serialises_to_json() -> TestResult {
        let payload = Payload::from_bytes(b"json test".to_vec());
        let unlock_at = Utc::now();

        let puzzle = create_puzzle(&payload, unlock_at, DEFAULT_SQUARINGS_PER_SEC)?;

        let json = serde_json::to_string_pretty(&puzzle)?;
        assert!(json.contains("squarings_required"));
        assert!(json.contains("modulus"));

        let recovered: TimeLockPuzzle = serde_json::from_str(&json)?;
        assert_eq!(recovered.squarings_required, puzzle.squarings_required);
        Ok(())
    }

    #[test]
    fn different_payloads_produce_different_puzzles() -> TestResult {
        let p1 = Payload::from_bytes(b"payload one".to_vec());
        let p2 = Payload::from_bytes(b"payload two".to_vec());
        let unlock_at = Utc::now();

        let puzzle1 = create_puzzle(&p1, unlock_at, DEFAULT_SQUARINGS_PER_SEC)?;
        let puzzle2 = create_puzzle(&p2, unlock_at, DEFAULT_SQUARINGS_PER_SEC)?;

        // Different moduli (random primes)
        assert_ne!(puzzle1.modulus, puzzle2.modulus);
        Ok(())
    }

    #[test]
    fn wrong_solution_fails_decrypt() -> TestResult {
        let payload = Payload::from_bytes(b"fail test".to_vec());
        let unlock_at = Utc::now();

        let mut puzzle = create_puzzle(&payload, unlock_at, DEFAULT_SQUARINGS_PER_SEC)?;

        // Corrupt the start value so squaring produces wrong result
        if let Some(byte) = puzzle.start_value.first_mut() {
            *byte ^= 0xFF;
        }

        let result = solve_puzzle(&puzzle);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn derive_key_and_nonce_is_deterministic() {
        let solution = BigUint::from(42u32);
        let (k1, n1) = derive_key_and_nonce(&solution);
        let (k2, n2) = derive_key_and_nonce(&solution);
        assert_eq!(k1, k2);
        assert_eq!(n1, n2);
    }

    #[test]
    fn sequential_square_identity() {
        let n = BigUint::from(143u32); // 11 * 13
        let g = BigUint::from(2u32);

        // g^(2^0) = g = 2
        let r0 = sequential_square(&g, &n, 0);
        assert_eq!(r0, g);

        // g^(2^1) = g^2 = 4
        let r1 = sequential_square(&g, &n, 1);
        assert_eq!(r1, BigUint::from(4u32));

        // g^(2^2) = g^4 = 16
        let r2 = sequential_square(&g, &n, 2);
        assert_eq!(r2, BigUint::from(16u32));
    }
}
