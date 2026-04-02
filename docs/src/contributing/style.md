# Code Style

## Formatting

The project uses `rustfmt` with settings in `rustfmt.toml`. Format before committing:

```bash
cargo fmt --all
```

## Lints

Clippy is configured at maximum strictness in `Cargo.toml`:

- `clippy::pedantic` — enabled
- `clippy::expect_used` — **denied** (no `.expect()` outside tests)
- `clippy::unwrap_used` — **denied** (no `.unwrap()` outside tests)
- `clippy::indexing_slicing` — **denied** (use `.get()` with explicit handling)

Run the full lint check:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

## Lint Suppression

Use `#[expect(lint)]` instead of `#[allow(lint)]`. The `expect` attribute warns if the suppressed lint stops firing, preventing stale suppressions from accumulating.

```rust
#[expect(clippy::cast_possible_truncation)]
fn small_index(n: usize) -> u8 {
    n as u8
}
```

## Error Handling

- All error types use `thiserror`.
- No `anyhow` in `domain/` or `adapters/`.
- Propagate errors with `?`. Match or `if let` when recovery is needed.

## Commits

Use [conventional commits](https://www.conventionalcommits.org/):

```
feat: add dead-drop platform support
fix: handle empty cover image gracefully
refactor: extract shard validation into helper
test: add ZWJ emoji round-trip tests
docs: document time-lock calibration
```

## Standard Library Preferences

Prefer modern standard library features over third-party crates:

| Prefer | Over |
|--------|------|
| `std::sync::LazyLock` | `lazy_static!`, `once_cell` |
| `Vec::extract_if` | manual filter/retain loops |
| `<[T]>::array_windows` | manual index arithmetic |
| `str::floor_char_boundary` | unchecked byte slicing |
| `strict_add` / `strict_sub` / `strict_mul` | `checked_add().unwrap()` |
