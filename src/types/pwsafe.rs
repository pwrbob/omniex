//! Password Safe hashes, rendered as `$pwsafe$*<version>*<salt>*<iterations>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Password Safe hashes in the `$pwsafe$` serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Password Safe", slug = "pwsafe", hashcat = [], john = ["pwsafe"])]
pub struct Pwsafe {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// 32-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Pwsafe {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pwsafe$*", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    9,
                    "invalid Password Safe version",
                )
            })?,
            salt: parse::decode_hex_field::<32>(fields[1].0, fields[1].1, "salt")?,
            iterations: fields[2].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid Password Safe iteration count",
                )
            })?,
            digest: parse::decode_hex_field::<32>(fields[3].0, fields[3].1, "digest")?,
        })
    }
}

impl Render for Pwsafe {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$pwsafe$*{}*{}*{}*{}",
            self.version,
            crate::format::hex(self.salt),
            self.iterations,
            crate::format::hex(self.digest)
        )
    }
}
