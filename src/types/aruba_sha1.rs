//! ArubaOS SHA-1, rendered as `<salt>01<digest>` in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// ArubaOS SHA-1 password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "ArubaOS SHA1",
    slug = "aruba-sha1",
    hashcat = [125],
)]
pub struct ArubaSha1 {
    /// The 4-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 4],

    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for ArubaSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 50 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "ArubaOS SHA1 must be 50 hexadecimal digits",
            ));
        }
        if &input[8..10] != "01" {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                8,
                "expected `01` signature after the salt",
            ));
        }

        Ok(Self {
            salt: parse::decode_hex_field::<4>(&input[..8], 0, "salt")?,
            digest: parse::decode_hex_field::<20>(&input[10..], 10, "digest")?,
        })
    }
}

impl Render for ArubaSha1 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}01{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
