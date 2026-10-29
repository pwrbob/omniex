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
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);

    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }

    out
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
