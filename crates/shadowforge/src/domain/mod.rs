//! Domain layer — pure business logic, no I/O.
//!
//! Sub-modules are bounded contexts. All share the canonical type
//! vocabulary defined in [`types`].

pub mod adaptive;
pub mod analysis;
pub mod archive;
pub mod canary;
pub mod corpus;
pub mod correction;
pub mod crypto;
pub mod deadrop;
pub mod deniable;
pub mod distribution;
pub mod errors;
pub mod media;
pub mod opsec;
pub mod pdf;
pub mod ports;
pub mod reconstruction;
pub mod scrubber;
pub mod stego;
pub mod timelock;
pub mod types;
