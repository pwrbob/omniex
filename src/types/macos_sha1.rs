//! macOS 10.4-10.6 SHA-1, rendered as `<salt><digest>` in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// macOS SHA-1 password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "macOS SHA1",
    slug = "macos-sha1",
    hashcat = [122],
)]
pub struct MacosSha1 {
    /// The 4-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 4],

    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for MacosSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 48 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "macOS SHA1 must be 48 hexadecimal digits",
            ));
        }

        Ok(Self {
            salt: parse::decode_hex_field::<4>(&input[..8], 0, "salt")?,
            digest: parse::decode_hex_field::<20>(&input[8..], 8, "digest")?,
        })
    }
}

impl Render for MacosSha1 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
