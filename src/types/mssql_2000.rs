//! MSSQL 2000, rendered as `0x0100<salt><padding><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MSSQL 2000 password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MSSQL (2000)",
    slug = "mssql-2000",
    hashcat = [131],
    john = ["mssql"],
)]
pub struct Mssql2000 {
    /// The 4-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 4],

    /// Reserved padding bytes, normally zero.
    #[field(role = other, encoding = hex)]
    pub padding: [u8; 20],

    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for Mssql2000 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "0x0100", 0)?;
        if rest.len() != 88 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6,
                "MSSQL 2000 body must be 88 hexadecimal digits",
            ));
        }

        Ok(Self {
            salt: parse::decode_hex_field::<4>(&rest[..8], 6, "salt")?,
            padding: parse::decode_hex_field::<20>(&rest[8..48], 14, "padding")?,
            digest: parse::decode_hex_field::<20>(&rest[48..], 54, "digest")?,
        })
    }
}

impl Render for Mssql2000 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!(
            "0x0100{}{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.padding),
            crate::format::hex(self.digest)
        )
    }
}
