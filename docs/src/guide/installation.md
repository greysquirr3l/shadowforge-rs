# Installation

## Prerequisites

- **Rust 1.94.1** or later (edition 2024)
- **pdfium** shared library (optional, for PDF rasterisation)

## From Source

```bash
# Clone the repository
git clone https://github.com/greysquirr3l/shadowforge-rs.git
cd shadowforge-rs

# Build in release mode (all default features enabled)
cargo build --release

# The binary is at target/release/shadowforge
```

## Cargo Features

shadowforge-rs uses optional features to control which capabilities are compiled in. This allows you to reduce the attack surface and build dependencies by disabling features you don't need.

### Available Features

| Feature | Default | Purpose |
|---------|---------|---------|
| `pdf` | ✅ | PDF embedding/extraction and page rasterisation (requires pdfium) |
| `corpus` | ✅ | Corpus-based steganography (zero-modification cover selection) |
| `adaptive` | ✅ | Adaptive embedding (STC-inspired steganalysis evasion) || `simd` | ❌ | SIMD-accelerated operations (for performance-critical deployments) |
### Building with Specific Features

```bash
# Disable all optional features
cargo build --release --no-default-features

# Disable only PDF support
cargo build --release --no-default-features --features corpus,adaptive

# Disable only adaptive embedding
cargo build --release --no-default-features --features pdf,corpus
```

## Verify Installation

```bash
shadowforge version
```

## PDF Support (Optional)

PDF page rasterisation requires the pdfium shared library. Without it, PDF content-stream and metadata steganography still work, but the render-to-PNG pipeline is unavailable.

The build process will auto-detect pdfium if:

- Set via the `PDFIUM_DYNAMIC_LIB_PATH` environment variable
- Found in a standard system library path:
  - macOS: `/opt/homebrew/lib` (Homebrew), `/opt/local/lib` (MacPorts), `/usr/local/lib`, `/usr/lib`
  - Linux: `/usr/local/lib`, `/usr/lib`, `/usr/lib/x86_64-linux-gnu`, `/usr/lib/aarch64-linux-gnu`
  - Windows: `C:\Program Files\pdfium\lib`, `C:\Program Files (x86)\pdfium\lib`

If pdfium is not found, the build will emit a warning. (Note: this warning only appears when the `pdf` feature is enabled; builds without it proceed silently.)

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
