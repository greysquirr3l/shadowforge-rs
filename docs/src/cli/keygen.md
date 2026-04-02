# keygen

Generate a post-quantum key pair.

## Usage

```bash
shadowforge keygen --algorithm <ALGORITHM> --output <DIR>
```

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `--algorithm` | Yes | `kyber1024` (ML-KEM-1024) or `dilithium3` (ML-DSA-87) |
| `--output` | Yes | Output directory for key files |

## Output

Creates two files in the output directory:

- `public.key` — the public key (safe to share)
- `secret.key` — the secret key (protect with your life)

## Examples

```bash
# Generate encryption keys
shadowforge keygen --algorithm kyber1024 --output ./enc-keys

# Generate signing keys
shadowforge keygen --algorithm dilithium3 --output ./sign-keys
```

## Security Notes

- Secret keys are zeroed from memory on drop (`ZeroizeOnDrop`).
- Store secret keys on encrypted storage. Consider amnesiac mode for key generation on sensitive systems.
- ML-KEM-1024 provides NIST Level 5 security against quantum adversaries.
- ML-DSA-87 provides NIST Level 5 signature security.
