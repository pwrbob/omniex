//! CHAP hashes, rendered as `$chap$<type>*<challenge>*<response>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// CHAP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "CHAP", slug = "chap", hashcat = [], john = ["chap"])]
pub struct Chap {
    /// CHAP type.
    #[field(role = other, encoding = decimal)]
    pub kind: u8,

    /// Sixteen-byte challenge.
    #[field(role = salt, encoding = hex)]
    pub challenge: [u8; 16],

    /// Sixteen-byte response.
    #[field(role = digest, encoding = hex)]
    pub response: [u8; 16],
}

impl Parse for Chap {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$chap$", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        Ok(Self {
            kind: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 6, "invalid CHAP type")
            })?,
            challenge: parse::decode_hex_field::<16>(fields[1].0, fields[1].1, "challenge")?,
            response: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "response")?,
        })
    }
}

impl Render for Chap {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$chap${}*{}*{}",
            self.kind,
            crate::format::hex(self.challenge),
            crate::format::hex(self.response)
        )
    }
}
