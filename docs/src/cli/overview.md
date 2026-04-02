# CLI Overview

shadowforge provides a single binary with subcommands grouped by function.

```
shadowforge <COMMAND>
```

## Core Commands

| Command | Description |
|---------|-------------|
| `version` | Print version and git SHA |
| `keygen` | Generate a post-quantum key pair |
| `embed` | Embed a payload into a cover medium |
| `extract` | Extract a hidden payload from a stego cover |
| `embed-distributed` | Split a payload across multiple covers with Reed-Solomon coding |
| `extract-distributed` | Reconstruct a payload from distributed stego covers |
| `analyse` | Estimate cover capacity and detectability |
| `archive` | Pack/unpack archive bundles (ZIP, TAR, TAR.GZ) |
| `completions` | Generate shell completion scripts |

## Countermeasure Commands

| Command | Threat Addressed |
|---------|-----------------|
| `scrub` | Stylometric source identification |
| `dead-drop` | Traffic analysis / sender-recipient linking |
| `time-lock` | Time-sensitive source protection |
| `watermark` | Internal leak attribution detection |
| `corpus` | Statistical steganalysis signature |

## Global Options

```
-h, --help     Print help
-V, --version  Print version
```

## Steganographic Techniques

Most commands accept a `--technique` flag. Available techniques:

| Value | Cover Type | Description |
|-------|-----------|-------------|
| `lsb` | PNG, BMP | Least-significant-bit substitution |
| `dct` | JPEG | DCT coefficient modulation |
| `palette` | GIF, indexed PNG | Palette index substitution |
| `lsb-audio` | WAV | Audio LSB substitution |
| `phase` | WAV | Phase encoding |
| `echo` | WAV | Echo hiding |
| `zero-width` | Plain text | Zero-width Unicode characters |
| `pdf-stream` | PDF | Content-stream LSB |
| `pdf-meta` | PDF | Metadata field embedding |
| `corpus` | Image set | Zero-modification cover selection |

## Embedding Profiles

The `embed` and `embed-distributed` commands support `--profile`:

| Profile | Behaviour |
|---------|-----------|
| `standard` | Default — no detectability constraint |
| `adaptive` | STC-inspired optimisation to bound detectability |
| `survivable` | Survives platform recompression (requires `--platform`) |
