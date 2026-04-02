# Quick Start

This guide walks through the most common workflow: generating keys, embedding a payload into a cover image, and extracting it.

## 1. Generate Keys

```bash
# Generate an ML-KEM-1024 key pair for encryption
shadowforge keygen --algorithm kyber1024 --output ./keys

# Generate an ML-DSA-87 key pair for signing
shadowforge keygen --algorithm dilithium3 --output ./keys-sign
```

This creates `public.key` and `secret.key` inside each output directory.

## 2. Embed a Payload

```bash
# Hide a file inside a PNG cover image using LSB steganography
shadowforge embed \
  --input secret-document.txt \
  --cover photo.png \
  --output stego-photo.png \
  --technique lsb
```

The output file looks identical to the original photo but carries the hidden payload.

## 3. Extract a Payload

```bash
# Recover the hidden file
shadowforge extract \
  --input stego-photo.png \
  --output recovered-document.txt \
  --technique lsb
```

## 4. Analyse Cover Capacity

Before embedding, check how much data a cover can hold:

```bash
shadowforge analyse \
  --input photo.png \
  --technique lsb \
  --format json
```

## Available Techniques

| Technique | Cover Type | Best For |
|-----------|-----------|----------|
| `lsb` | PNG, BMP | Large payloads in lossless images |
| `dct` | JPEG | Lossy images (survives recompression) |
| `palette` | GIF, indexed PNG | Small payloads in palette images |
| `lsb-audio` | WAV | Audio covers |
| `phase` | WAV | Phase-encoded audio (more robust) |
| `echo` | WAV | Echo-hidden audio |
| `zero-width` | Plain text | Text covers (zero-width Unicode) |
| `pdf-content` | PDF | PDF content-stream LSB |
| `pdf-metadata` | PDF | PDF metadata fields |
| `corpus` | Image corpus | Zero-modification cover selection |

## Next Steps

- [Distributed embedding](../cli/embed-distributed.md) for splitting payloads across multiple covers
- [Threat model](../threats/overview.md) to understand what shadowforge protects against
- [Operational security](../opsec/overview.md) for real-world usage procedures
