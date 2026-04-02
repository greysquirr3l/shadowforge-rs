# extract

Extract a hidden payload from a stego cover.

## Usage

```bash
shadowforge extract --input <FILE> --output <FILE> --technique <TECHNIQUE> [OPTIONS]
```

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `--input` | Yes | Path to the stego file |
| `--output` | Yes | Output path for the extracted payload |
| `--technique` | Yes | Steganographic technique |
| `--key` | No | Key path for deniable extraction |
| `--amnesia` | No | Read from stdin, write to stdout |

## Examples

```bash
# Basic extraction
shadowforge extract \
  --input stego.png --output recovered.txt --technique lsb

# Extract with deniable key (real payload)
shadowforge extract \
  --input stego.png --output recovered.txt \
  --technique lsb --key ./primary.key

# Extract decoy payload (under compulsion)
shadowforge extract \
  --input stego.png --output decoy.txt \
  --technique lsb --key ./decoy.key

# Amnesiac extraction
cat stego.png | shadowforge extract \
  --output /dev/stdout --technique lsb --amnesia > recovered.txt
```
