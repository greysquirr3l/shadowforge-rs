# Installation

## Prerequisites

- **Rust 1.94.1** or later (edition 2024)
- **pdfium** shared library (optional, for PDF rasterisation)

## From Source

```bash
# Clone the repository
git clone https://github.com/greysquirr3l/shadowforge-rs.git
cd shadowforge-rs

# Build in release mode
cargo build --release

# The binary is at target/release/shadowforge
```

## Verify Installation

```bash
shadowforge version
```

## PDF Support (Optional)

PDF page rasterisation requires the pdfium shared library. Without it, PDF content-stream and metadata steganography still work, but the render-to-PNG pipeline is unavailable.

### macOS (Apple Silicon)

```bash
curl -L https://github.com/bblanchon/pdfium-binaries/releases/latest/download/pdfium-mac-arm64.tgz | tar xz
export PDFIUM_DYNAMIC_LIB_PATH="$(pwd)/lib"
```

### macOS (Intel)

```bash
curl -L https://github.com/bblanchon/pdfium-binaries/releases/latest/download/pdfium-mac-x64.tgz | tar xz
export PDFIUM_DYNAMIC_LIB_PATH="$(pwd)/lib"
```

### Linux (x86_64)

```bash
curl -L https://github.com/bblanchon/pdfium-binaries/releases/latest/download/pdfium-linux-x64.tgz | tar xz
export PDFIUM_DYNAMIC_LIB_PATH="$(pwd)/lib"
```

## Shell Completions

See [Shell Completions](./completions.md) for setting up tab completion in your shell.
