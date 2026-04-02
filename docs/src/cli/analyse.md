# analyse

Estimate cover capacity and detectability for a given technique.

## Usage

```bash
shadowforge analyse --cover <FILE> --technique <TECHNIQUE> [--json]
```

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `--cover` | Yes | Path to the cover file |
| `--technique` | Yes | Steganographic technique |
| `--json` | No | Output as JSON instead of a table |

## Examples

```bash
# Human-readable output
shadowforge analyse --cover photo.png --technique lsb

# JSON output (for scripting)
shadowforge analyse --cover photo.png --technique lsb --json
```

## Output

The analysis reports:

- **Capacity**: Maximum payload size in bytes
- **Technique**: The steganographic method used
- **Chi-square score**: Detectability metric (lower is less detectable)
