# watermark

Embed and detect forensic watermarks to trace the origin of leaked copies.

## Usage

```bash
shadowforge watermark <COMMAND>
```

## Subcommands

### embed

Embed a unique recipient fingerprint into a cover.

```bash
shadowforge watermark embed \
  --cover <FILE> --recipient <ID> --output <FILE>
```

### detect

Check a file for watermark fingerprints.

```bash
shadowforge watermark detect \
  --input <FILE> --tags <FILE>
```

## Examples

```bash
# Watermark a document for a specific recipient
shadowforge watermark embed \
  --cover report.png --recipient "recipient-uuid" --output report-wm.png

# Check if a leaked copy contains a known watermark
shadowforge watermark detect \
  --input leaked.png --tags known-recipients.json
```

## How It Works

Each recipient gets a unique permutation pattern embedded via LSB. If a copy is leaked, `watermark detect` matches it against known recipient tags to identify the source of the leak.
