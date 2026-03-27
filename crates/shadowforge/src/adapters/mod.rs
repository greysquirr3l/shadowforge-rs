//! Infrastructure adapters implementing domain port traits.

pub mod correction;
pub mod crypto;
pub mod media;

#[cfg(feature = "pdf")]
pub mod pdf;

pub mod stego;
