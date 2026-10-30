//! macOS 10.7 SHA-512, rendered as `<salt><digest>` in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// macOS 10.7 SHA-512 password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "macOS SHA512",
    slug = "macos-sha512",
    hashcat = [1722],
)]
pub struct MacosSha512 {
    /// The 4-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 4],

    /// The 64-byte SHA-512 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for MacosSha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 136 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "macOS SHA512 hash must be 136 hexadecimal digits",
            ));
        }

        Ok(Self {
            salt: parse::decode_hex_field::<4>(&input[..8], 0, "salt")?,
            digest: parse::decode_hex_field::<64>(&input[8..], 8, "digest")?,
        })
    }
}

impl Render for MacosSha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
