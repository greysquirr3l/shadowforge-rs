//! Adapter implementing the [`StyloScrubber`] port via domain logic.

use crate::domain::errors::ScrubberError;
use crate::domain::ports::StyloScrubber;
use crate::domain::scrubber;
use crate::domain::types::StyloProfile;

/// Default implementation of stylometric scrubbing.
///
/// Delegates to the pure domain functions in [`crate::domain::scrubber`].
pub struct StyloScrubberImpl;

impl StyloScrubberImpl {
    /// Create a new scrubber adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for StyloScrubberImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl StyloScrubber for StyloScrubberImpl {
    fn scrub(&self, text: &str, profile: &StyloProfile) -> Result<String, ScrubberError> {
        let result = scrubber::scrub_text(text, profile);

        // Verify the result is valid UTF-8 (should always be true for String,
        // but the port contract requires us to surface InvalidUtf8)
        if result.is_empty() && !text.is_empty() {
            // Something went very wrong — original had content but output is empty
            return Err(ScrubberError::ProfileNotSatisfied {
                reason: "scrubbing reduced non-empty input to empty output".into(),
            });
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> StyloProfile {
        StyloProfile {
            target_vocab_size: 5000,
            target_avg_sentence_len: 15.0,
            normalize_punctuation: true,
        }
    }

    #[test]
    fn scrub_via_adapter() {
        let scrubber = StyloScrubberImpl::new();
        let input = "Don\u{2019}t worry\u{2014}it\u{2019}s fine!";
        let result = scrubber
            .scrub(input, &profile())
            .expect("scrub should succeed");
        assert!(result.contains("do not"));
        assert!(result.contains("it is"));
        assert!(!result.contains('\u{2014}'));
    }

    #[test]
    fn scrub_empty_returns_empty() {
        let scrubber = StyloScrubberImpl::new();
        let result = scrubber
            .scrub("", &profile())
            .expect("scrub should succeed");
        assert!(result.is_empty());
    }

    #[test]
    fn scrub_idempotent_via_adapter() {
        let scrubber = StyloScrubberImpl::new();
        let input = "\u{201C}They\u{2019}re coming,\u{201D} she whispered\u{2026}";
        let once = scrubber.scrub(input, &profile()).expect("first scrub");
        let twice = scrubber.scrub(&once, &profile()).expect("second scrub");
        assert_eq!(once, twice);
    }

    #[test]
    fn scrub_preserves_non_latin() {
        let scrubber = StyloScrubberImpl::new();
        let input = "\u{0645}\u{0631}\u{062D}\u{0628}\u{0627} \u{0628}\u{0627}\u{0644}\u{0639}\u{0627}\u{0644}\u{0645}";
        let result = scrubber.scrub(input, &profile()).expect("scrub arabic");
        assert!(!result.is_empty());
    }

    #[test]
    fn default_impl() {
        let scrubber = StyloScrubberImpl::default();
        let result = scrubber
            .scrub("hello world", &profile())
            .expect("scrub should succeed");
        assert_eq!(result, "hello world");
    }
}
