# Stylometric Identification

## Threat

Adversaries use stylometric analysis (Writeprints, JStylo) to identify the author of anonymous text by analysing sentence length, vocabulary, punctuation patterns, and other linguistic features.

## Countermeasure: StyloScrubber

The `StyloScrubber` normalises text against a generic frequency table:

- Adjusts average sentence length to a configurable target
- Constrains vocabulary to a target size
- Smooths punctuation distribution

```bash
shadowforge scrub --input article.txt --output scrubbed.txt \
  --avg-sentence-len 12 --vocab-size 800
```

Or inline during embedding:

```bash
shadowforge embed --input article.txt --cover photo.png --output stego.png \
  --technique lsb --scrub-style
```

## Residual Risk

Stylometric scrubbing is statistical and partial. A determined adversary with a large corpus of the author's known writing may still identify residual patterns. This is a risk-reduction measure, not a guarantee of anonymity.
