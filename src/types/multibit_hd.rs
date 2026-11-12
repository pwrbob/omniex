//! MultiBit HD wallet hashes, rendered as
//! `$multibit$<version>*<salt>*<encrypted key>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MultiBit HD wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "MultiBit HD (scrypt)", slug = "multibit-hd", hashcat = [22700])]
pub struct MultibitHd {
    /// Format version, always `2`
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// 16-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// 16-byte encrypted key
    #[field(role = ciphertext, encoding = hex)]
    pub encrypted: [u8; 16],

    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for MultibitHd {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$multibit$", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        let version = fields[0].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid MultiBit HD version",
            )
        })?;
        Ok(Self {
            version,
            salt: parse::decode_hex_field::<16>(fields[1].0, fields[1].1, "salt")?,
            encrypted: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "encrypted key")?,
            digest: parse::decode_hex_field::<16>(fields[3].0, fields[3].1, "digest")?,
        })
    }
}

impl Render for MultibitHd {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$multibit${}*{}*{}*{}",
            self.version,
            crate::format::hex(self.salt),
            crate::format::hex(self.encrypted),
            crate::format::hex(self.digest)
        )
    }
}
