# Development Setup

## Prerequisites

- **Rust 1.94.1** (stable). The project pins this in `rust-toolchain.toml`.
- **cargo-deny** for supply-chain checks: `cargo install cargo-deny`
- **mdbook** for documentation: `cargo install mdbook`

## Clone and Build

```bash
git clone https://github.com/greysquirr3l/shadowforge-rs.git
cd shadowforge-rs
cargo build --workspace
```

## Verify

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo deny check
```

## Optional: PDFium

PDF rasterisation requires the PDFium shared library. On macOS:

```bash
brew install pdfium
```

On Linux, download the prebuilt binary from [pdfium-binaries](https://github.com/nickcampbell/nickcampbell/pdfium-binaries) and place it on `LD_LIBRARY_PATH`.

## Editor Setup

The project includes `.vscode/settings.json` with rust-analyzer configuration. VS Code with the rust-analyzer extension will pick up lints and formatting automatically.
