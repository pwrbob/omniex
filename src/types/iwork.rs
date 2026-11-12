//! Apple iWork, rendered as `$iwork$<hash version>$<file version>$<format>$<iterations>$<salt>$<iv>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Apple iWork encrypted documents.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Apple iWork",
    slug = "iwork",
    hashcat = [23300], john = ["iwork"],
)]
pub struct Iwork {
    /// Hash version
    #[field(role = other, encoding = decimal)]
    pub hash_version: u8,

    /// File version
    #[field(role = other, encoding = decimal)]
    pub file_version: u8,

    /// Format version
    #[field(role = other, encoding = decimal)]
    pub format_version: u8,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// IV
    #[field(role = iv, encoding = hex)]
    pub iv: [u8; 16],

    /// Encrypted data
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

impl Parse for Iwork {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$iwork$", 0)?;
        let fields = parse::split_fields(rest, '$', 7)?;
        Ok(Self {
            hash_version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    7,
                    "invalid iWork hash version",
                )
            })?,
            file_version: fields[1].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid iWork file version",
                )
            })?,
            format_version: fields[2].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid iWork format version",
                )
            })?,
            iterations: fields[3].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[3].1,
                    "invalid iWork iteration count",
                )
            })?,
            salt: parse::decode_hex(fields[4].0, fields[4].1)?,
            iv: parse::decode_hex_field::<16>(fields[5].0, fields[5].1, "iv")?,
            data: parse::decode_hex(fields[6].0, fields[6].1)?,
        })
    }
}

impl Render for Iwork {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$iwork${}${}${}${}${}${}${}",
            self.hash_version,
            self.file_version,
            self.format_version,
            self.iterations,
            crate::format::hex(&self.salt),
            crate::format::hex(self.iv),
            crate::format::hex(&self.data)
        )
    }
}
