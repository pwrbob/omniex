//! VTP hashes, rendered as `$vtp$<version>$<length>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// VTP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "VTP", slug = "vtp", hashcat = [], john = ["vtp"])]
pub struct Vtp {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Data length.
    #[field(role = other, encoding = decimal)]
    pub length: u32,

    /// Packet data.
    #[field(role = ciphertext, encoding = ascii)]
    pub data: String,
}

impl Parse for Vtp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$vtp$", 0)?;
        let mut fields = rest.splitn(3, '$');
        let version = fields.next().unwrap_or_default();
        let length = fields.next().unwrap_or_default();
        let data = fields.next().ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidLength,
                rest.len(),
                "missing VTP data",
            )
        })?;
        Ok(Self {
            version: version.parse::<u8>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 5, "invalid VTP version")
            })?,
            length: length.parse::<u32>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 7, "invalid VTP length")
            })?,
            data: data.to_owned(),
        })
    }
}

impl Render for Vtp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$vtp${}${}${}", self.version, self.length, self.data)
    }
}
