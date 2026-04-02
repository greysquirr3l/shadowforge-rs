# dead-drop

Encode a payload for posting on a public platform without direct file transfer.

## Usage

```bash
shadowforge dead-drop \
  --cover <FILE> --input <FILE> --platform <PLATFORM> --output <FILE> [OPTIONS]
```

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `--cover` | Yes | Cover image path |
| `--input` | Yes | Payload file path |
| `--platform` | Yes | Target platform |
| `--output` | Yes | Output stego file |
| `--technique` | No | Steganographic technique (defaults to platform-appropriate) |

## Supported Platforms

| Platform | Recompression |
|----------|--------------|
| `instagram` | Aggressive JPEG |
| `twitter` | JPEG |
| `whatsapp` | JPEG |
| `telegram` | Moderate JPEG |
| `imgur` | JPEG |

## Examples

```bash
# Prepare a dead-drop image for Twitter
shadowforge dead-drop \
  --cover photo.jpg --input secret.txt \
  --platform twitter --output post.jpg
```

## How It Works

1. The payload is embedded using a technique that survives the target platform's recompression.
2. The output image is posted publicly (e.g. uploaded to Twitter).
3. The recipient downloads the image and extracts using `shadowforge extract`.

This eliminates direct sender-recipient communication channels, defeating traffic analysis.
