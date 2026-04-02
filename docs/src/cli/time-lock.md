# time-lock

Create time-lock puzzle payloads that cannot be opened before a specified duration.

## Usage

```bash
shadowforge time-lock <COMMAND>
```

## Subcommands

### lock

```bash
shadowforge time-lock lock \
  --input <FILE> --output <FILE> --duration <SECONDS>
```

### unlock

```bash
shadowforge time-lock unlock \
  --input <FILE> --output <FILE>
```

## Examples

```bash
# Lock a payload for 24 hours (86400 seconds)
shadowforge time-lock lock \
  --input secret.txt --output locked.bin --duration 86400

# Unlock (requires sequential computation)
shadowforge time-lock unlock \
  --input locked.bin --output recovered.txt
```

## How It Works

Uses Rivest's iterated squaring scheme: the payload is encrypted with a key that can only be derived by performing a sequential chain of modular squarings. No amount of parallelism can speed this up.

> **Important**: Time-lock puzzles provide a practical delay, not a cryptographic guarantee. Hardware advances may reduce the effective delay. Do not rely on this as the sole time-based protection.
