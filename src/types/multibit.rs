//! MultiBit Classic .key, rendered as `$multibit$<version>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MultiBit Classic .key hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MultiBit Classic .key (MD5)",
    slug = "multibit",
    hashcat = [22500], john = ["multibit"],
)]
pub struct Multibit {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// 8-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Multibit {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$multibit$", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    10,
                    "invalid MultiBit version",
                )
            })?,
            salt: parse::decode_hex_field::<8>(fields[1].0, fields[1].1, "salt")?,
            digest: parse::decode_hex_field::<32>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for Multibit {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$multibit${}*{}*{}",
            self.version,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
