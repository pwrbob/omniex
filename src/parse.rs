//! Parsing helpers shared by concrete hash types.

use crate::{ParseError, ParseErrorKind};

/// Builds an error for empty input.
#[must_use]
pub fn empty() -> ParseError {
    ParseError {
        kind: ParseErrorKind::Empty,
        offset: 0,
        message: "input is empty".to_owned(),
    }
}

/// Builds a parse error.
#[must_use]
pub fn error(kind: ParseErrorKind, offset: usize, message: impl Into<String>) -> ParseError {
    ParseError {
        kind,
        offset,
        message: message.into(),
    }
}

/// Decodes a string of hexadecimal bytes.
///
/// `base` is the byte offset of `input` in the original hash string.
pub fn decode_hex(input: &str, base: usize) -> Result<Vec<u8>, ParseError> {
    if input.len() % 2 != 0 {
        return Err(error(
            ParseErrorKind::InvalidLength,
            base + input.len(),
            "hexadecimal value must have an even number of digits",
        ));
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);

    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0]).ok_or_else(|| {
            error(
                ParseErrorKind::InvalidHex,
                base + index * 2,
                "invalid hexadecimal digit",
            )
        })?;
        let low = hex_digit(pair[1]).ok_or_else(|| {
            error(
                ParseErrorKind::InvalidHex,
                base + index * 2 + 1,
                "invalid hexadecimal digit",
            )
        })?;
        out.push((high << 4) | low);
    }

    Ok(out)
}

/// Decodes exactly `N` hexadecimal bytes.
pub fn decode_hex_array<const N: usize>(input: &str, base: usize) -> Result<[u8; N], ParseError> {
    let bytes = decode_hex(input, base)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        error(
            ParseErrorKind::InvalidLength,
            base,
            format!("expected {N} bytes, found {}", bytes.len()),
        )
    })
}

/// Decodes a hexadecimal field of exactly `N` bytes, with a field name in the
/// error message.
pub fn decode_hex_field<const N: usize>(
    input: &str,
    base: usize,
    field: &str,
) -> Result<[u8; N], ParseError> {
    if input.len() != N * 2 {
        return Err(error(
            ParseErrorKind::InvalidLength,
            base,
            format!("{field} must be {} hexadecimal digits", N * 2),
        ));
    }
    decode_hex_array::<N>(input, base)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_lower_and_upper_hex() {
        assert_eq!(decode_hex("00aF", 0).unwrap(), vec![0x00, 0xaf]);
    }

    #[test]
    fn rejects_odd_length() {
        let error = decode_hex("abc", 4).unwrap_err();
        assert_eq!(error.kind, ParseErrorKind::InvalidLength);
        assert_eq!(error.offset, 7);
    }

    #[test]
    fn reports_absolute_offset_for_bad_digit() {
        let error = decode_hex("zz", 10).unwrap_err();
        assert_eq!(error.kind, ParseErrorKind::InvalidHex);
        assert_eq!(error.offset, 10);
    }
}
