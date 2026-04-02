# Countermeasure Commands

These commands address specific nation-state adversary capabilities. Each maps to a threat in the [threat model](../threats/overview.md).

| Command | Threat | Description |
|---------|--------|-------------|
| [`scrub`](./scrub.md) | Stylometric identification | Normalise writing patterns |
| [`dead-drop`](./dead-drop.md) | Traffic analysis | Platform-aware public posting |
| [`time-lock`](./time-lock.md) | Time-sensitive sources | Delayed-reveal payloads |
| [`watermark`](./watermark.md) | Insider attribution | Recipient fingerprinting |
| [`corpus`](./corpus.md) | Statistical steganalysis | Zero-modification cover selection |

These capabilities are also available as flags on the core `embed` command:

- `--scrub-style` — inline stylometric scrubbing
- `--deniable` — dual-payload deniable embedding
- `--amnesia` — zero disk writes
- `--profile adaptive` — bounded detectability
- `--profile survivable --platform <P>` — compression survival
