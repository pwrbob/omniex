//! AxCrypt 1, rendered as `$axcrypt$*1*<iterations>*<salt>*<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AxCrypt 1 encrypted files.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "AxCrypt 1",
    slug = "axcrypt1",
    hashcat = [13200],
)]
pub struct Axcrypt1 {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// The 16-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// Hexadecimal data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

impl Parse for Axcrypt1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$axcrypt$*", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    10,
                    "invalid AxCrypt version",
                )
            })?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid AxCrypt iteration count",
                )
            })?,
            salt: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "salt")?,
            data: parse::decode_hex(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for Axcrypt1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$axcrypt$*{}*{}*{}*{}",
            self.version,
            self.iterations,
            crate::format::hex(self.salt),
            crate::format::hex(&self.data)
        )
    }
}
