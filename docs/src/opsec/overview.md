# Operational Security Overview

This section introduces the operational security principles behind shadowforge. Detailed scenario-based playbooks (border crossings, dead drops, geographic distribution, time-lock workflows, and zero-trace procedures) are available in the source repository under `docs/src/opsec/` but are intentionally excluded from the published site.

> **Why?** Algorithmic details and CLI references follow Kerckhoffs's principle — publishing them does not weaken the system. Operational playbooks, however, describe *human behaviour patterns* that an adversary could use to fingerprint shadowforge users. Keeping them repo-only means they are accessible to anyone who clones the source, but not indexed or browsable by casual reconnaissance.

> **Prerequisite**: Familiarise yourself with the [threat model](../threats/overview.md) before planning any operation. Understanding which threats apply to your situation determines which countermeasures to deploy.

## Available Playbooks (repo only)

| Playbook | File | Primary Threats |
|----------|------|-----------------|
| Crossing a Border | `docs/src/opsec/border-crossing.md` | Compelled decryption, device seizure |
| Dead Drop via Public Platform | `docs/src/opsec/dead-drop.md` | Traffic analysis, surveillance |
| Geographic Distribution | `docs/src/opsec/geographic.md` | Jurisdictional pressure |
| Time-Lock Source Protection | `docs/src/opsec/time-lock.md` | Time-sensitive compromise |
| Zero-Trace Operation | `docs/src/opsec/zero-trace.md` | Endpoint forensics |

To read these, clone the repository and open the files directly.

## General Principles

1. **Layer your defences.** No single countermeasure is sufficient. Combine steganographic concealment with encrypted channels (Signal), network anonymity (Tor), and operational discipline.

2. **Test your procedures.** Before using shadowforge in a high-stakes situation, practice the full workflow (embed → transfer → extract) in a safe environment.

3. **Verify key material.** Always verify public keys through an out-of-band channel before trusting them.

4. **Destroy after use.** Use `zeroize` discipline — or better, amnesiac mode — to ensure key material doesn't persist.
