//! Money hashes, rendered as `$money$<version>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Money hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Money", slug = "money", hashcat = [], john = ["money"])]
pub struct Money {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Eight-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// Four-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 4],
}

impl Parse for Money {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$money$", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 7, "invalid Money version")
            })?,
            salt: parse::decode_hex_field::<8>(fields[1].0, fields[1].1, "salt")?,
            digest: parse::decode_hex_field::<4>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for Money {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$money${}*{}*{}",
            self.version,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
