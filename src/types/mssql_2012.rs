//! MSSQL 2012/2014, rendered as `0x0200<salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MSSQL 2012/2014 password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MSSQL (2012, 2014)",
    slug = "mssql-2012",
    hashcat = [1731],
    john = ["mssql12"],
)]
pub struct Mssql2012 {
    /// The 4-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 4],

    /// The 64-byte SHA-512 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for Mssql2012 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "0x0200", 0)?;
        if rest.len() != 136 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6,
                "MSSQL 2012 body must be 136 hexadecimal digits",
            ));
        }

        Ok(Self {
            salt: parse::decode_hex_field::<4>(&rest[..8], 6, "salt")?,
            digest: parse::decode_hex_field::<64>(&rest[8..], 14, "digest")?,
        })
    }
}

impl Render for Mssql2012 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "0x0200{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
