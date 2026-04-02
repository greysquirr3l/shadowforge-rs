# embed-distributed

Split a payload into Reed-Solomon coded shards and embed each into a separate cover.

## Usage

```bash
shadowforge embed-distributed \
  --input <FILE> --covers <GLOB> --output-archive <FILE> \
  --technique <TECHNIQUE> [OPTIONS]
```

## Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--input` | Yes | | Payload file |
| `--covers` | Yes | | Glob pattern for cover files |
| `--output-archive` | Yes | | Output archive path |
| `--technique` | Yes | | Steganographic technique |
| `--data-shards` | No | 3 | Number of data shards |
| `--parity-shards` | No | 2 | Number of parity shards |
| `--profile` | No | `standard` | Embedding profile |
| `--platform` | No | | Target platform (for `survivable`) |
| `--canary` | No | | Inject a canary shard for tamper detection |
| `--geo-manifest` | No | | Geographic distribution manifest (TOML) |

## Examples

```bash
# Distribute across 5 covers (3 data + 2 parity)
shadowforge embed-distributed \
  --input secret.txt \
  --covers "covers/*.png" \
  --output-archive distributed.zip \
  --technique lsb

# With canary shard
shadowforge embed-distributed \
  --input secret.txt \
  --covers "covers/*.png" \
  --output-archive distributed.zip \
  --technique lsb --canary

# Geographic distribution
shadowforge embed-distributed \
  --input secret.txt \
  --covers "covers/*.png" \
  --output-archive distributed.zip \
  --technique lsb \
  --geo-manifest manifest.toml
```

## How It Works

1. The payload is split into `data-shards` pieces.
2. `parity-shards` additional pieces are generated via Reed-Solomon coding.
3. Each shard is embedded into a separate cover file.
4. All stego covers are packed into the output archive.

Recovery requires **any** `data-shards` of the total shards. With the default 3+2 configuration, any 3 of 5 shards reconstruct the original payload.
