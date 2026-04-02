# Threat Model Overview

shadowforge-rs is designed for the **journalist-vs-nation-state** threat model. The primary adversary has:

- Infrastructure-scale automated steganalysis (Aletheia, StegExpose)
- Legal authority to compel decryption
- Traffic analysis capabilities across ISPs and platforms
- Endpoint access (device seizure, forensic imaging)
- Stylometric analysis capabilities
- Jurisdictional legal pressure across borders

## Threat-to-Countermeasure Map

| # | Threat | Countermeasure | Command / Flag |
|---|--------|---------------|----------------|
| 1 | [Automated steganalysis](./steganalysis.md) | Adaptive embedding, cover profile matching, compression survival, corpus selection | `--profile adaptive`, `--profile survivable`, `corpus select` |
| 2 | [Compelled decryption](./compelled-decryption.md) | Deniable embedding, panic wipe, time-lock | `--deniable`, `panic`, `time-lock lock` |
| 3 | [Traffic analysis](./traffic-analysis.md) | Dead drop mode, platform-aware embedding | `dead-drop` |
| 4 | [Endpoint compromise](./endpoint-compromise.md) | Amnesiac mode, ZeroizeOnDrop | `--amnesia` |
| 5 | [Legal/jurisdictional pressure](./legal-pressure.md) | Geographic threshold distribution, canary shards | `--geo-manifest`, `--canary` |
| 6 | [Stylometric identification](./stylometry.md) | StyloScrubber | `scrub`, `--scrub-style` |
| 7 | Internal leak attribution | Forensic watermarker | `watermark embed/detect` |

## What shadowforge Does NOT Protect Against

See [Residual Risks](./residual-risks.md) for limitations and scenarios where shadowforge is insufficient.
