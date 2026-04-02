# corpus

Corpus steganography — zero-modification cover selection via ANN search.

## Usage

```bash
shadowforge corpus <COMMAND>
```

## Subcommands

### index

Build an index over a local image corpus.

```bash
shadowforge corpus index --dir <DIR> --output <FILE>
```

### select

Select the best-matching cover from the corpus for a given payload.

```bash
shadowforge corpus select \
  --index <FILE> --payload <FILE> --output <FILE>
```

## Examples

```bash
# Build a corpus index from a photo library
shadowforge corpus index --dir ~/Photos --output corpus.idx

# Find the cover whose existing LSB pattern best matches the payload
shadowforge corpus select \
  --index corpus.idx --payload secret.txt --output best-cover.png
```

## How It Works

Instead of modifying a cover to embed data, corpus steganography searches a large collection of images to find one whose existing statistical properties naturally encode (or closely match) the payload bits.

This produces **zero modifications** to the selected cover, making steganalysis detection theoretically impossible — the cover has never been altered.

> **Requirement**: This technique requires a sufficiently large corpus of cover images to find good matches. Effectiveness scales with corpus size.
