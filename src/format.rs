//! Formatting helpers used by generated `describe` implementations.

pub use omniex_core::format::hex;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

/// Formats bytes as standard base64 with padding.
#[must_use]
pub fn base64(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes)
}

/// Formats bytes as standard base64 without padding.
#[must_use]
pub fn base64_no_pad(bytes: impl AsRef<[u8]>) -> String {
    STANDARD_NO_PAD.encode(bytes)
}
