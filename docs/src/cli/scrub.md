# scrub

Scrub text of stylometric fingerprints to resist authorship attribution.

## Usage

```bash
shadowforge scrub --input <FILE> --output <FILE> [OPTIONS]
```

## Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--input` | Yes | | Input text file |
| `--output` | Yes | | Output file |
| `--avg-sentence-len` | No | 15 | Target average sentence length |
| `--vocab-size` | No | 1000 | Target vocabulary size |

## Examples

```bash
shadowforge scrub --input article.txt --output scrubbed.txt

# Custom parameters for more aggressive normalisation
shadowforge scrub --input article.txt --output scrubbed.txt \
  --avg-sentence-len 12 --vocab-size 800
```

## How It Works

The scrubber normalises your writing against a frequency table, adjusting sentence length distribution and vocabulary complexity to match a generic baseline. This makes stylometric analysis (e.g. Writeprints, JStylo) less effective at identifying the author.

> **Limitation**: Stylometric scrubbing is statistical and partial. A determined adversary with a large writing sample may still find residual patterns. Use this alongside other countermeasures, not as a sole defence.
