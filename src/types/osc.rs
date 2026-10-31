//! OSC hashes, rendered as `$OSC$<year>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// OSC hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "OSC", slug = "osc", hashcat = [], john = ["osc"])]
pub struct Osc {
    /// Year.
    #[field(role = other, encoding = decimal)]
    pub year: u16,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Osc {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$OSC$", 0)?;
        let (year, digest, digest_offset) = parse::split_once(rest, '$', 5)?;
        Ok(Self {
            year: year.parse::<u16>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 5, "invalid OSC year")
            })?,
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Osc {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$OSC${}${}", self.year, crate::format::hex(self.digest))
    }
}
