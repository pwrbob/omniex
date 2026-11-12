//! PGP SDA hashes, rendered as `$pgpsda$<version>*<iterations>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PGP SDA hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PGP SDA", slug = "pgpsda", hashcat = [], john = ["pgpsda"])]
pub struct Pgpsda {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// 8-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// 8-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for Pgpsda {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pgpsda$", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    8,
                    "invalid PGP SDA version",
                )
            })?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid PGP SDA iteration count",
                )
            })?,
            salt: parse::decode_hex_field::<8>(fields[2].0, fields[2].1, "salt")?,
            digest: parse::decode_hex_field::<8>(fields[3].0, fields[3].1, "digest")?,
        })
    }
}

impl Render for Pgpsda {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$pgpsda${}*{}*{}*{}",
            self.version,
            self.iterations,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
