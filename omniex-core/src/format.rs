//! Formatting helpers used by generated `describe` implementations.

/// Formats bytes as lowercase hexadecimal.
///
/// # Examples
///
/// ```
/// assert_eq!(omniex_core::format::hex([0xde_u8, 0xad, 0xbe, 0xef]), "deadbeef");
/// ```
#[must_use]
pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::hex;

    #[test]
    fn formats_empty_input() {
        assert_eq!(hex([0_u8; 0]), "");
    }

    #[test]
    fn formats_bytes_as_lowercase_hex() {
        assert_eq!(hex([0x00, 0x0f, 0x10, 0xff]), "000f10ff");
    }
}
