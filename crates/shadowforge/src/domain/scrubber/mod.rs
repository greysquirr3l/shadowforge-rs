//! Linguistic stylometric fingerprint scrubbing.
//!
//! Deterministic statistical normalisation of text to destroy authorship
//! attribution fingerprints. No LLM, no network calls — purely local
//! text transformation.

use unicode_segmentation::UnicodeSegmentation;

use crate::domain::types::StyloProfile;

/// Normalise punctuation to ASCII equivalents.
///
/// Smart quotes → ASCII, em-dashes → `--`, ellipses → `...`.
#[must_use]
pub fn normalize_punctuation(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' => result.push('\''),
            '\u{201C}' | '\u{201D}' | '\u{201E}' | '\u{201F}' => result.push('"'),
            '\u{2013}' | '\u{2014}' => result.push_str("--"),
            '\u{2026}' => result.push_str("..."),
            '\u{00A0}' => result.push(' '), // non-breaking space
            _ => result.push(ch),
        }
    }
    result
}

/// Expand common English contractions to full forms.
#[must_use]
pub fn expand_contractions(text: &str) -> String {
    // Process word by word, preserving whitespace structure
    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    for (start, word) in text.unicode_word_indices() {
        // Preserve any whitespace/punctuation before this word
        result.push_str(&text[last_end..start]);
        last_end = start + word.len();

        // Check for contractions in the surrounding context
        let lower = word.to_lowercase();
        let expansion = match lower.as_str() {
            "don't" => Some("do not"),
            "doesn't" => Some("does not"),
            "didn't" => Some("did not"),
            "won't" => Some("will not"),
            "wouldn't" => Some("would not"),
            "couldn't" => Some("could not"),
            "shouldn't" => Some("should not"),
            "isn't" => Some("is not"),
            "aren't" => Some("are not"),
            "wasn't" => Some("was not"),
            "weren't" => Some("were not"),
            "haven't" => Some("have not"),
            "hasn't" => Some("has not"),
            "hadn't" => Some("had not"),
            "can't" => Some("cannot"),
            "it's" => Some("it is"),
            "i'm" => Some("I am"),
            "i've" => Some("I have"),
            "i'll" => Some("I will"),
            "i'd" => Some("I would"),
            "we're" => Some("we are"),
            "we've" => Some("we have"),
            "we'll" => Some("we will"),
            "they're" => Some("they are"),
            "they've" => Some("they have"),
            "they'll" => Some("they will"),
            "you're" => Some("you are"),
            "you've" => Some("you have"),
            "you'll" => Some("you will"),
            "he's" => Some("he is"),
            "she's" => Some("she is"),
            "that's" => Some("that is"),
            "there's" => Some("there is"),
            "here's" => Some("here is"),
            "what's" => Some("what is"),
            "who's" => Some("who is"),
            "let's" => Some("let us"),
            _ => None,
        };

        if let Some(expanded) = expansion {
            result.push_str(expanded);
        } else {
            result.push_str(word);
        }
    }

    // Append any trailing text after the last word
    if last_end < text.len() {
        result.push_str(&text[last_end..]);
    }

    result
}

/// Count words in a sentence using grapheme-aware word boundaries.
fn word_count(sentence: &str) -> usize {
    sentence.unicode_words().count()
}

/// Apply all scrubbing transformations to the input text.
///
/// Operations applied:
/// 1. Punctuation normalisation (if `profile.normalize_punctuation`)
/// 2. Contraction expansion
/// 3. Whitespace normalisation
#[must_use]
pub fn scrub_text(text: &str, profile: &StyloProfile) -> String {
    if text.is_empty() {
        return String::new();
    }

    let mut result = text.to_owned();

    // Step 1: Normalise punctuation
    if profile.normalize_punctuation {
        result = normalize_punctuation(&result);
    }

    // Step 2: Expand contractions
    result = expand_contractions(&result);

    // Step 3: Normalise whitespace (collapse runs of spaces)
    result = collapse_whitespace(&result);

    result
}

/// Collapse runs of whitespace into single spaces, trimming leading/trailing.
fn collapse_whitespace(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut prev_was_space = true; // trim leading
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !prev_was_space {
                result.push(' ');
            }
            prev_was_space = true;
        } else {
            result.push(ch);
            prev_was_space = false;
        }
    }
    // Trim trailing space
    if result.ends_with(' ') {
        result.pop();
    }
    result
}

/// Compute the average sentence length in words for the given text.
#[must_use]
pub fn average_sentence_length(text: &str) -> f64 {
    let sentences: Vec<&str> = text.split_sentence_bounds().collect();
    let sentence_words: Vec<usize> = sentences
        .iter()
        .map(|s| word_count(s))
        .filter(|&count| count > 0)
        .collect();

    if sentence_words.is_empty() {
        return 0.0;
    }

    let total_words: usize = sentence_words.iter().sum();
    #[expect(clippy::cast_precision_loss, reason = "sentence counts never exceed 2^52")]
    {
        total_words as f64 / sentence_words.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punctuation_normalisation_smart_quotes() {
        let input = "\u{201C}Hello,\u{201D} she said. \u{2018}Goodbye.\u{2019}";
        let output = normalize_punctuation(input);
        assert_eq!(output, "\"Hello,\" she said. 'Goodbye.'");
    }

    #[test]
    fn punctuation_normalisation_em_dashes() {
        let input = "word\u{2014}another";
        let output = normalize_punctuation(input);
        assert_eq!(output, "word--another");
    }

    #[test]
    fn punctuation_normalisation_ellipsis() {
        let input = "wait\u{2026}";
        let output = normalize_punctuation(input);
        assert_eq!(output, "wait...");
    }

    #[test]
    fn contraction_expansion() {
        let input = "I can't believe they're here.";
        let output = expand_contractions(input);
        assert!(output.contains("cannot"));
        assert!(output.contains("they are"));
    }

    #[test]
    fn scrub_idempotent() {
        let profile = StyloProfile {
            target_vocab_size: 5000,
            target_avg_sentence_len: 15.0,
            normalize_punctuation: true,
        };
        let input = "Don't worry\u{2014}it's fine!";
        let once = scrub_text(input, &profile);
        let twice = scrub_text(&once, &profile);
        assert_eq!(once, twice);
    }

    #[test]
    fn non_latin_passes_through() {
        let profile = StyloProfile {
            target_vocab_size: 5000,
            target_avg_sentence_len: 15.0,
            normalize_punctuation: true,
        };
        let arabic = "\u{0645}\u{0631}\u{062D}\u{0628}\u{0627} \u{0628}\u{0627}\u{0644}\u{0639}\u{0627}\u{0644}\u{0645}";
        let output = scrub_text(arabic, &profile);
        // Should pass through without panic or data loss
        assert!(!output.is_empty());
    }

    #[test]
    fn chinese_passes_through() {
        let profile = StyloProfile {
            target_vocab_size: 5000,
            target_avg_sentence_len: 15.0,
            normalize_punctuation: false,
        };
        let chinese = "\u{4F60}\u{597D}\u{4E16}\u{754C}";
        let output = scrub_text(chinese, &profile);
        assert_eq!(output, chinese);
    }

    #[test]
    fn whitespace_collapse() {
        let input = "  hello   world  ";
        let output = collapse_whitespace(input);
        assert_eq!(output, "hello world");
    }

    #[test]
    fn average_sentence_length_basic() {
        let text = "Hello world. This is a test.";
        let avg = average_sentence_length(text);
        assert!(avg > 1.0);
    }

    #[test]
    fn empty_text_scrubs_to_empty() {
        let profile = StyloProfile {
            target_vocab_size: 5000,
            target_avg_sentence_len: 15.0,
            normalize_punctuation: true,
        };
        let output = scrub_text("", &profile);
        assert!(output.is_empty());
    }
}
