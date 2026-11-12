//! Bitwarden, rendered as `$bitwarden$<version>*<iterations>*<kdf>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Bitwarden master password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Bitwarden",
    slug = "bitwarden",
    hashcat = [23400],
)]
pub struct Bitwarden {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// KDF identifier
    #[field(role = other, encoding = decimal)]
    pub kdf: u8,

    /// Salt
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// Digest
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for Bitwarden {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$bitwarden$", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    11,
                    "invalid Bitwarden version",
                )
            })?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid Bitwarden iteration count",
                )
            })?,
            kdf: fields[2].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid Bitwarden KDF",
                )
            })?,
            salt: parse::decode_base64(fields[3].0, fields[3].1)?,
            digest: parse::decode_base64(fields[4].0, fields[4].1)?,
        })
    }
}

impl Render for Bitwarden {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$bitwarden${}*{}*{}*{}*{}",
            self.version,
            self.iterations,
            self.kdf,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.digest)
        )
    }
}
