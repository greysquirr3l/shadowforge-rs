# extract-distributed

Reconstruct a payload from distributed stego covers.

## Usage

```bash
shadowforge extract-distributed \
  --input-archive <FILE> --output <FILE> --technique <TECHNIQUE> [OPTIONS]
```

## Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--input-archive` | Yes | | Input archive or directory path |
| `--output` | Yes | | Output path for the recovered payload |
| `--technique` | Yes | | Steganographic technique |
| `--data-shards` | No | 3 | Number of data shards in the original split |
| `--parity-shards` | No | 2 | Number of parity shards in the original split |

## Examples

```bash
# Reconstruct from archive
shadowforge extract-distributed \
  --input-archive distributed.zip \
  --output recovered.txt \
  --technique lsb

# Custom shard counts
shadowforge extract-distributed \
  --input-archive distributed.zip \
  --output recovered.txt \
  --technique lsb \
  --data-shards 5 --parity-shards 3
```

## Fault Tolerance

If some shards are missing or corrupted, Reed-Solomon coding can reconstruct the original payload as long as at least `data-shards` valid shards remain. With 3+2 defaults, losing any 2 shards is tolerable.
