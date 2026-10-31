//! Signal hashes, rendered as a `$signal$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Signal hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Signal", slug = "signal", hashcat = [], john = ["Signal"])]
pub struct Signal {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Sixteen-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Remaining data.
    #[field(role = ciphertext, encoding = ascii)]
    pub data: String,
}

impl Parse for Signal {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$signal$", 0)?;
        let parts = rest.splitn(5, '$').collect::<Vec<_>>();
        if parts.len() < 5 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                rest.len(),
                "Signal hashes have at least five fields",
            ));
        }
        Ok(Self {
            version: parts[0].parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    9,
                    "invalid Signal version",
                )
            })?,
            iterations: parts[1].parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    11,
                    "invalid Signal iteration count",
                )
            })?,
            salt: parse::decode_hex_field::<16>(parts[2], 0, "salt")?,
            digest: parse::decode_hex_field::<16>(parts[3], 0, "digest")?,
            data: parts[4].to_owned(),
        })
    }
}

impl Render for Signal {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$signal${}${}${}${}${}",
            self.version,
            self.iterations,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest),
            self.data
        )
    }
}
