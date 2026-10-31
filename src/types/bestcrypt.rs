//! BestCrypt volumes, rendered as `$bcve$<version>$<key size>$<salt>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// BestCrypt volume hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "BestCrypt",
    slug = "bestcrypt",
    hashcat = [23900, 24000], john = ["BestCryptVE4"],
    modes_fn = bestcrypt_modes,
)]
pub struct Bestcrypt {
    /// Format version, which selects the mode.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Key size identifier.
    #[field(role = other, encoding = ascii)]
    pub key_size: String,

    /// Hexadecimal salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Hexadecimal data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

pub fn bestcrypt_modes(value: &Bestcrypt) -> Vec<crate::Mode> {
    match value.version {
        3 => vec![crate::Mode::Hashcat(23900)],
        4 => vec![crate::Mode::Hashcat(24000)],
        _ => Vec::new(),
    }
}

impl Parse for Bestcrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$bcve$", 0)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    6,
                    "invalid BestCrypt version",
                )
            })?,
            key_size: fields[1].0.to_owned(),
            salt: fields[2].0.to_owned(),
            data: parse::decode_hex(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for Bestcrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$bcve${}${}${}${}",
            self.version,
            self.key_size,
            self.salt,
            crate::format::hex(&self.data)
        )
    }
}
