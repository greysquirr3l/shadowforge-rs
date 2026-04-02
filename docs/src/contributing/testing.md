# Testing Standards

## Running Tests

```bash
cargo test --workspace
```

All tests must also pass single-threaded (no test-global mutable state):

```bash
cargo test --workspace -- --test-threads=1
```

## Coverage Targets

| Module | Minimum Coverage |
|--------|-----------------|
| `domain/crypto/` | 90% |
| Overall | 85% |

Coverage is enforced in CI via `cargo-tarpaulin`.

## Requirements

- Every public function in `domain/` and `application/` must have at least one test.
- All tests that touch key material must call `zeroize()` on temporaries before assertions.
- CLI integration tests use the `assert_cmd` crate.
- Unicode tests must include Arabic, Thai, Devanagari, and emoji ZWJ inputs.

## Writing Tests

Tests live alongside the code they test, in `#[cfg(test)]` modules:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode_round_trips() {
        // ...
    }
}
```

`.unwrap()` and `.expect()` are permitted inside `#[cfg(test)]` blocks but nowhere else.

## What to Test

- **Round-trip correctness.** Encode then decode; encrypt then decrypt; split then reassemble.
- **Edge cases.** Empty input, single-byte input, maximum capacity.
- **Error paths.** Invalid keys, corrupted shards, truncated ciphertext.
- **Unicode safety.** Multi-byte grapheme clusters, bidirectional text, ZWJ emoji sequences.
- **Zeroing.** Confirm that key material is zeroed after use.
