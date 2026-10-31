//! RADIUS hashes, rendered as `$radius$<version>*<type>*<secret>*<digest>*<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// RADIUS hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "RADIUS", slug = "radius", hashcat = [], john = ["radius"])]
pub struct Radius {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Authentication type.
    #[field(role = other, encoding = decimal)]
    pub kind: u8,

    /// Shared secret.
    #[field(role = salt, encoding = ascii)]
    pub secret: String,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Sixteen-byte authenticator data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 16],
}

impl Parse for Radius {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$radius$", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    8,
                    "invalid RADIUS version",
                )
            })?,
            kind: fields[1].0.parse::<u8>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 10, "invalid RADIUS type")
            })?,
            secret: fields[2].0.to_owned(),
            digest: parse::decode_hex_field::<16>(fields[3].0, fields[3].1, "digest")?,
            data: parse::decode_hex_field::<16>(fields[4].0, fields[4].1, "data")?,
        })
    }
}

impl Render for Radius {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$radius${}*{}*{}*{}*{}",
            self.version,
            self.kind,
            self.secret,
            crate::format::hex(self.digest),
            crate::format::hex(self.data)
        )
    }
}
