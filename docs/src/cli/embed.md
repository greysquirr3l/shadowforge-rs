# embed

Embed a payload into a cover medium.

## Usage

```bash
shadowforge embed --input <FILE> --cover <FILE> --output <FILE> --technique <TECHNIQUE> [OPTIONS]
```

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `--input` | Yes | Path to the payload file |
| `--cover` | No | Cover medium (omit for amnesiac mode) |
| `--output` | Yes | Output path for the stego file |
| `--technique` | Yes | Steganographic technique (see [overview](./overview.md)) |
| `--profile` | No | `standard` (default), `adaptive`, or `survivable` |
| `--platform` | No | Target platform (required when profile = `survivable`) |
| `--amnesia` | No | Read cover from stdin, write stego to stdout |
| `--scrub-style` | No | Scrub text payload before embedding |
| `--deniable` | No | Enable dual-payload deniable embedding |
| `--decoy-payload` | No | Decoy payload path (with `--deniable`) |
| `--decoy-key` | No | Decoy key path (with `--deniable`) |
| `--key` | No | Primary key path (with `--deniable`) |

## Examples

```bash
# Basic LSB embedding
shadowforge embed \
  --input secret.txt --cover photo.png --output stego.png --technique lsb

# Adaptive embedding (bounded detectability)
shadowforge embed \
  --input secret.txt --cover photo.png --output stego.png \
  --technique lsb --profile adaptive

# Compression-survivable for Instagram
shadowforge embed \
  --input secret.txt --cover photo.jpg --output stego.jpg \
  --technique dct --profile survivable --platform instagram

# Deniable embedding (dual payloads)
shadowforge embed \
  --input real-secret.txt --cover photo.png --output stego.png \
  --technique lsb --deniable \
  --key ./primary.key --decoy-payload decoy.txt --decoy-key ./decoy.key

# Amnesiac mode (zero disk writes)
cat cover.png | shadowforge embed \
  --input secret.txt --output /dev/stdout --technique lsb --amnesia > stego.png

# Embed with stylometric scrubbing
shadowforge embed \
  --input article-draft.txt --cover photo.png --output stego.png \
  --technique lsb --scrub-style
```
