//! PGP Disk hashes, rendered as `$pgpdisk$<version>*<count>*<iterations>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PGP Disk hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PGP Disk", slug = "pgpdisk", hashcat = [], john = ["pgpdisk"])]
pub struct Pgpdisk {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Cipher count
    #[field(role = other, encoding = decimal)]
    pub count: u8,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// 16-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Pgpdisk {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pgpdisk$", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    9,
                    "invalid PGP Disk version",
                )
            })?,
            count: fields[1].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    11,
                    "invalid PGP Disk count",
                )
            })?,
            iterations: fields[2].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid PGP Disk iteration count",
                )
            })?,
            salt: parse::decode_hex_field::<16>(fields[3].0, fields[3].1, "salt")?,
            digest: parse::decode_hex_field::<16>(fields[4].0, fields[4].1, "digest")?,
        })
    }
}

impl Render for Pgpdisk {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$pgpdisk${}*{}*{}*{}*{}",
            self.version,
            self.count,
            self.iterations,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
