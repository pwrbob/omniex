//! MSSQL 2005, rendered as `0x0100<salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MSSQL 2005 password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MSSQL (2005)",
    slug = "mssql-2005",
    hashcat = [132],
    john = ["mssql05"],
)]
pub struct Mssql2005 {
    /// The 4-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 4],

    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for Mssql2005 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "0x0100", 0)?;
        if rest.len() != 48 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6,
                "MSSQL 2005 body must be 48 hexadecimal digits",
            ));
        }

        Ok(Self {
            salt: parse::decode_hex_field::<4>(&rest[..8], 6, "salt")?,
            digest: parse::decode_hex_field::<20>(&rest[8..], 14, "digest")?,
        })
    }
}

impl Render for Mssql2005 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!(
            "0x0100{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
