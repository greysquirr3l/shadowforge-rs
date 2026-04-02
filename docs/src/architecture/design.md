# Design Philosophy

shadowforge-rs uses a **collapsed hexagonal** (ports-and-adapters) architecture with **DDD-lite** bounded contexts.

## Why Hexagonal?

The core domain logic — cryptographic operations, steganographic encoding, Reed-Solomon correction — must be pure and testable without I/O. Hexagonal architecture enforces this by pushing all external interactions behind port traits.

```
┌─────────────────────────────────────────────┐
│                 interface/                   │
│              (CLI, future API)               │
├─────────────────────────────────────────────┤
│               application/                  │
│          (orchestration services)            │
├──────────────┬──────────────────────────────┤
│   domain/    │         adapters/            │
│  (pure logic │   (I/O, FFI, filesystem)     │
│   + ports)   │                              │
└──────────────┴──────────────────────────────┘
```

Dependencies always point inward:

- **adapters/** imports port traits from **domain/** and implements them.
- **application/** accepts port trait references and orchestrates domain logic.
- **interface/** constructs concrete adapters, wires them into application services, and handles user interaction.
- **domain/** imports nothing from the outer layers. It defines the vocabulary, the rules, and the contracts.

## Why "Collapsed"?

A full hexagonal architecture separates each bounded context into its own crate with explicit port modules. shadowforge-rs collapses this into a single crate with module boundaries instead of crate boundaries. The workspace structure (`crates/`) is intentional: future companion crates (e.g. `shadowforge-web`, `shadowforge-api`) add as new members without restructuring the core.

## Why DDD-lite?

Each bounded context (crypto, stego, correction, etc.) owns its own logic and interacts with others only through the shared type vocabulary in `domain/types.rs` and the port traits in `domain/ports.rs`. There are no full aggregate roots or repository patterns — the "lite" means we take the context-boundary discipline without the ceremony.
