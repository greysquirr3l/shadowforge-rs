//! Adversarial embedding optimisation, camera model profile matching,
//! compression-survivable embedding.
//!
//! Pure domain logic — no I/O, no file system, no async runtime.

use rand::RngExt as _;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::domain::analysis::pair_delta_chi_square_score;
use crate::domain::ports::CoverProfile;

// ─── BinMask ─────────────────────────────────────────────────────────────────

/// Occupancy mask for 2-D FFT bins, built from a [`CoverProfile`].
///
/// A `true` entry at `(row, col)` means that bin is occupied by a known
/// external signal (e.g. an AI generator's watermark carrier) and **must
/// not** be used for payload embedding.
pub struct BinMask {
    width: u32,
    height: u32,
    /// Row-major flat array; index = `row * width + col`.
    occupied: Vec<bool>,
}

impl BinMask {
    /// Build a bin-occupancy mask from `profile` at the given resolution.
    ///
    /// - `CoverProfile::Camera` → all-zeros (no protected bins).
    /// - `CoverProfile::AiGenerator` → marks strong carrier bins
    ///   (`coherence >= 0.90`).
    #[must_use]
    pub fn build(profile: &CoverProfile, width: u32, height: u32) -> Self {
        let len = (width as usize).strict_mul(height as usize);
        let mut occupied = vec![false; len];

        if let CoverProfile::AiGenerator(p) = profile
            && let Some(bins) = p.carrier_bins_for(width, height)
        {
            for bin in bins.iter().filter(|b| b.is_strong()) {
                let (row, col) = bin.freq;
                if row < height && col < width {
                    let idx = (row as usize)
                        .strict_mul(width as usize)
                        .strict_add(col as usize);
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "idx < len is guaranteed by the row/col range check above"
                    )]
                    {
                        occupied[idx] = true;
                    }
                }
            }
        }

        Self {
            width,
            height,
            occupied,
        }
    }

    /// Return `true` if the bin at `(row, col)` is marked as occupied.
    #[must_use]
    pub fn is_occupied(&self, row: u32, col: u32) -> bool {
        if row >= self.height || col >= self.width {
            return false;
        }
        let idx = (row as usize)
            .strict_mul(self.width as usize)
            .strict_add(col as usize);
        self.occupied.get(idx).copied().unwrap_or(false)
    }

    /// Return the number of occupied bins.
    #[must_use]
    pub fn occupied_count(&self) -> usize {
        self.occupied.iter().filter(|&&b| b).count()
    }

    /// Total number of bins in the mask.
    #[must_use]
    pub const fn total_bins(&self) -> usize {
        self.occupied.len()
    }
}

// ─── Cost function ───────────────────────────────────────────────────────────

/// Per-bit-position distortion cost for the adaptive permutation search.
///
/// Returns `f64::INFINITY` for positions that map to occupied FFT bins.
/// Returns a value in `1.0..=2.0` for safe bins — higher near
/// moderate-coherence bins as a soft margin.
#[must_use]
pub fn cost_at(bit_position: usize, total_positions: usize, mask: &BinMask) -> f64 {
    if total_positions == 0 {
        return f64::INFINITY;
    }

    let Ok(width) = usize::try_from(mask.width.max(1)) else {
        return f64::INFINITY;
    };
    let col_usize = bit_position % width;
    let row_usize = bit_position / width;
    let Ok(col) = u32::try_from(col_usize) else {
        return f64::INFINITY;
    };
    let Ok(row) = u32::try_from(row_usize) else {
        return f64::INFINITY;
    };

    if mask.is_occupied(row, col) {
        return f64::INFINITY;
    }

    // Soft margin: positions near the boundary of occupied regions get a
    // slightly higher cost (up to 2.0).  We use the fractional position
    // within the image as a proxy for proximity to occupied areas.
    let bit_position_f = u32::try_from(bit_position)
        .ok()
        .map_or_else(|| f64::from(u32::MAX), f64::from);
    let total_positions_f = u32::try_from(total_positions)
        .ok()
        .map_or_else(|| f64::from(u32::MAX), f64::from);
    let fraction = bit_position_f / total_positions_f;
    1.0 + fraction.min(1.0)
}

// ─── Permutation ─────────────────────────────────────────────────────────────

/// A bit-position permutation derived from a cost-weighted PRNG walk.
///
/// `map[original_position] = new_position`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permutation {
    map: Vec<usize>,
}

impl Permutation {
    /// Identity permutation — no reordering.
    #[must_use]
    pub fn identity(len: usize) -> Self {
        Self {
            map: (0..len).collect(),
        }
    }

    /// Apply the permutation to `data` in-place (cycle-following algorithm).
    pub fn apply(&self, data: &mut [u8]) {
        let n = data.len().min(self.map.len());
        let source = match data.get(..n) {
            Some(slice) => slice.to_vec(),
            None => return,
        };
        let mut dest = source.clone();

        for (original_position, &new_position) in self.map.iter().take(n).enumerate() {
            if new_position >= n {
                continue;
            }
            if let (Some(dst), Some(&src)) =
                (dest.get_mut(new_position), source.get(original_position))
            {
                *dst = src;
            }
        }

        if let Some(target) = data.get_mut(..n) {
            target.copy_from_slice(&dest);
        }
    }

    /// Return the inverse permutation  such that `inv.apply(p.apply(x)) == x`.
    #[must_use]
    pub fn inverse(&self) -> Self {
        let mut inv = vec![0usize; self.map.len()];
        for (orig, &new_pos) in self.map.iter().enumerate() {
            if new_pos < inv.len() {
                #[expect(
                    clippy::indexing_slicing,
                    reason = "new_pos is within bounds by the range-check above"
                )]
                {
                    inv[new_pos] = orig;
                }
            }
        }
        Self { map: inv }
    }

    /// Raw permutation map (`original_position -> new_position`).
    #[must_use]
    pub fn as_slice(&self) -> &[usize] {
        &self.map
    }
}

// ─── SearchConfig ────────────────────────────────────────────────────────────

/// Permutation search configuration.
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Maximum number of candidate permutations to evaluate.
    pub max_iterations: u32,
    /// Target chi-square score (dB) — search stops early when reached.
    pub target_db: f64,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_iterations: 100,
            target_db: -12.0,
        }
    }
}

// ─── permutation_search ──────────────────────────────────────────────────────

/// Find the lowest-detectability permutation within `config.max_iterations`.
///
/// `seed` must be derived from the crypto key — never use a fresh random seed
/// (the receiver needs to reconstruct the same permutation for extraction).
///
/// Uses a random-restart hill-climb: each iteration proposes a swap of two
/// positions and accepts it if it lowers the chi-square score.
#[must_use]
pub fn permutation_search(
    stego_bytes: &[u8],
    mask: &BinMask,
    config: &SearchConfig,
    seed: u64,
) -> Permutation {
    if stego_bytes.is_empty() || config.max_iterations == 0 {
        return Permutation::identity(stego_bytes.len());
    }

    let n = stego_bytes.len();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut best_perm = Permutation::identity(n);
    // Use pair-delta chi-square (order-sensitive) so that swapping bytes
    // actually changes the score and the hill-climb can make progress.
    let mut best_score = pair_delta_chi_square_score(stego_bytes);

    // Collect safe (non-occupied) positions to limit candidate swaps.
    let safe_positions: Vec<usize> = (0..n)
        .filter(|&pos| cost_at(pos, n, mask).is_finite())
        .collect();

    if safe_positions.len() < 2 {
        return best_perm;
    }

    let mut current_map = best_perm.map.clone();
    let mut current_data = stego_bytes.to_vec();

    for _ in 0..config.max_iterations {
        // Pick two distinct safe positions.
        let idx_a = rng.random_range(0..safe_positions.len());
        let mut idx_b = rng.random_range(0..safe_positions.len());
        while idx_b == idx_a {
            idx_b = rng.random_range(0..safe_positions.len());
        }
        let (Some(&pos_a), Some(&pos_b)) = (safe_positions.get(idx_a), safe_positions.get(idx_b))
        else {
            continue;
        };

        // Tentatively swap in both the map and the data.
        current_map.swap(pos_a, pos_b);
        current_data.swap(pos_a, pos_b);

        let score = pair_delta_chi_square_score(&current_data);
        if score < best_score {
            best_score = score;
            best_perm = Permutation {
                map: current_map.clone(),
            };
            if best_score <= config.target_db {
                break;
            }
        } else {
            // Revert.
            current_map.swap(pos_a, pos_b);
            current_data.swap(pos_a, pos_b);
        }
    }

    best_perm
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ports::{AiGenProfile, CarrierBin, CoverProfile};
    use std::collections::HashMap;

    fn gemini_1024_profile() -> CoverProfile {
        let bins = vec![
            CarrierBin::new((9, 9), 0.0, 1.0),
            CarrierBin::new((5, 5), 0.0, 1.0),
            CarrierBin::new((10, 11), 0.0, 1.0),
            CarrierBin::new((13, 6), 0.0, 0.82), // below 0.90 — NOT strong
        ];
        let mut carrier_map = HashMap::new();
        carrier_map.insert("1024x1024".to_string(), bins);
        CoverProfile::AiGenerator(AiGenProfile {
            model_id: "gemini".to_string(),
            channel_weights: [0.85, 1.0, 0.70],
            carrier_map,
        })
    }

    #[test]
    fn camera_profile_yields_all_zeros_mask() {
        use crate::domain::ports::CameraProfile;
        let profile = CoverProfile::Camera(CameraProfile {
            quantisation_table: [0u16; 64],
            noise_floor_db: -80.0,
            model_id: "canon".to_string(),
        });
        let mask = BinMask::build(&profile, 64, 64);
        assert_eq!(mask.occupied_count(), 0);
    }

    #[test]
    fn ai_gen_profile_marks_strong_carrier_bins() {
        let profile = gemini_1024_profile();
        let mask = BinMask::build(&profile, 1024, 1024);
        // (9,9), (5,5), (10,11) are strong; (13,6) has coherence 0.82 — not marked
        assert!(mask.is_occupied(9, 9));
        assert!(mask.is_occupied(5, 5));
        assert!(mask.is_occupied(10, 11));
        assert!(!mask.is_occupied(13, 6)); // below 0.90
        assert!(!mask.is_occupied(100, 100));
        assert_eq!(mask.occupied_count(), 3);
    }

    #[test]
    fn cost_at_returns_infinity_for_occupied_bin() {
        let profile = gemini_1024_profile();
        let mask = BinMask::build(&profile, 1024, 1024);
        // Position for (row=9, col=9): index = 9 * 1024 + 9 = 9225
        let occupied_position = 9usize * 1024 + 9;
        let cost = cost_at(occupied_position, 1024 * 1024, &mask);
        assert!(cost.is_infinite(), "expected infinity for occupied bin");
    }

    #[test]
    fn cost_at_returns_finite_for_safe_bin() {
        let profile = gemini_1024_profile();
        let mask = BinMask::build(&profile, 1024, 1024);
        let safe_position = 500usize;
        let cost = cost_at(safe_position, 1024 * 1024, &mask);
        assert!(cost.is_finite());
        assert!(cost >= 1.0);
        assert!(cost <= 2.0);
    }

    #[test]
    fn permutation_zero_iterations_returns_identity() {
        let data = vec![1u8, 2, 3, 4, 5, 6];
        let mask = BinMask::build(
            &CoverProfile::Camera(crate::domain::ports::CameraProfile {
                quantisation_table: [0u16; 64],
                noise_floor_db: -80.0,
                model_id: "test".to_string(),
            }),
            6,
            1,
        );
        let config = SearchConfig {
            max_iterations: 0,
            target_db: -12.0,
        };
        let perm = permutation_search(&data, &mask, &config, 42);
        assert_eq!(perm, Permutation::identity(6));
    }

    #[test]
    fn permutation_is_deterministic_same_seed() {
        let data: Vec<u8> = (0u8..64).collect();
        let mask = BinMask::build(
            &CoverProfile::Camera(crate::domain::ports::CameraProfile {
                quantisation_table: [0u16; 64],
                noise_floor_db: -80.0,
                model_id: "test".to_string(),
            }),
            8,
            8,
        );
        let config = SearchConfig::default();
        let p1 = permutation_search(&data, &mask, &config, 12345);
        let p2 = permutation_search(&data, &mask, &config, 12345);
        assert_eq!(p1, p2);
    }

    #[test]
    fn permutation_inverse_round_trips() {
        let data: Vec<u8> = vec![10, 20, 30, 40, 50];
        let mask = BinMask::build(
            &CoverProfile::Camera(crate::domain::ports::CameraProfile {
                quantisation_table: [0u16; 64],
                noise_floor_db: -80.0,
                model_id: "test".to_string(),
            }),
            5,
            1,
        );
        let config = SearchConfig::default();
        let perm = permutation_search(&data, &mask, &config, 99);
        let original = data.clone();
        let mut modified = data;
        perm.apply(&mut modified);
        perm.inverse().apply(&mut modified);
        assert_eq!(modified, original);
    }

    #[test]
    fn permutation_identity_apply_is_noop() {
        let original = vec![1u8, 2, 3, 4];
        let mut data = original.clone();
        let perm = Permutation::identity(4);
        perm.apply(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn permutation_search_may_improve_score() {
        // Build stego data with a known non-uniform pattern.
        // The permutation search may find a better ordering.
        let mut data: Vec<u8> = (0u8..=255u8).collect();
        data.extend_from_slice(&[0u8; 256]); // add 256 zeros → heavily skewed histogram
        let mask = BinMask::build(
            &CoverProfile::Camera(crate::domain::ports::CameraProfile {
                quantisation_table: [0u16; 64],
                noise_floor_db: -80.0,
                model_id: "test".to_string(),
            }),
            16,
            32,
        );
        let config = SearchConfig {
            max_iterations: 100,
            target_db: -12.0,
        };
        let perm = permutation_search(&data, &mask, &config, 777);
        // The permutation must be the right size.
        assert_eq!(perm.as_slice().len(), data.len());
        // After applying and inverting we must recover the original.
        let original = data.clone();
        let mut applied = data;
        perm.apply(&mut applied);
        perm.inverse().apply(&mut applied);
        assert_eq!(applied, original);
    }
}
