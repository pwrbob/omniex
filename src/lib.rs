//! `omniex` public facade: hash types, registry, and derive re-export.
//!
//! The data model lives in `omniex-core`. This crate holds the concrete hash
//! types and the registry the CLI dispatches through.

extern crate self as omniex;

pub use omniex_core::*;
pub use omniex_macros::HashType;

pub mod format;

pub mod parse;
pub mod registry;
pub mod types;
