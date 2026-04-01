//! Time-lock adapter implementing the [`TimeLockService`] port.

use chrono::{DateTime, Utc};

use crate::domain::errors::TimeLockError;
use crate::domain::ports::TimeLockService;
use crate::domain::timelock;
use crate::domain::types::{Payload, TimeLockPuzzle};

/// Adapter delegating to the domain time-lock implementation.
pub struct TimeLockServiceImpl {
    /// Estimated squarings per second on current hardware.
    squarings_per_sec: u64,
}

impl TimeLockServiceImpl {
    /// Create a new time-lock service with the given calibration.
    #[must_use]
    pub const fn new(squarings_per_sec: u64) -> Self {
        Self { squarings_per_sec }
    }
}

impl Default for TimeLockServiceImpl {
    fn default() -> Self {
        Self::new(timelock::default_squarings_per_sec())
    }
}

impl TimeLockService for TimeLockServiceImpl {
    fn lock(
        &self,
        payload: &Payload,
        unlock_at: DateTime<Utc>,
    ) -> Result<TimeLockPuzzle, TimeLockError> {
        timelock::create_puzzle(payload, unlock_at, self.squarings_per_sec)
    }

    fn unlock(&self, puzzle: &TimeLockPuzzle) -> Result<Payload, TimeLockError> {
        timelock::solve_puzzle(puzzle)
    }

    fn try_unlock(&self, puzzle: &TimeLockPuzzle) -> Result<Option<Payload>, TimeLockError> {
        timelock::try_solve_puzzle(puzzle, self.squarings_per_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_roundtrip() {
        let service = TimeLockServiceImpl::default();
        let payload = Payload::from_bytes(b"adapter test".to_vec());
        let unlock_at = Utc::now();

        let puzzle = service.lock(&payload, unlock_at).expect("lock");
        let recovered = service.unlock(&puzzle).expect("unlock");

        assert_eq!(recovered.as_bytes(), payload.as_bytes());
    }

    #[test]
    fn adapter_try_unlock_returns_none_for_future() {
        let service = TimeLockServiceImpl::default();
        let payload = Payload::from_bytes(b"future test".to_vec());
        let unlock_at = Utc::now() + chrono::Duration::hours(24);

        let puzzle = service.lock(&payload, unlock_at).expect("lock");
        let result = service.try_unlock(&puzzle).expect("try_unlock");

        assert!(result.is_none());
    }
}
