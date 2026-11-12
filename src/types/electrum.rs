//! Electrum wallets, rendered as `$electrum$<version>*<salt>*<data>[*<mac>]`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Electrum wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Electrum Wallet",
    slug = "electrum",
    hashcat = [16600, 21700, 21800], john = ["electrum", "electrum-modern-opencl"],
    modes_fn = electrum_modes,
)]
pub struct Electrum {
    /// Wallet format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Hexadecimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Encrypted data
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,

    /// MAC (may be empty)
    #[field(role = digest, encoding = hex)]
    pub mac: Vec<u8>,
}

pub fn electrum_modes(value: &Electrum) -> Vec<crate::Mode> {
    match value.version {
        1..=3 => vec![crate::Mode::Hashcat(16600)],
        4 => vec![crate::Mode::Hashcat(21700)],
        5 => vec![crate::Mode::Hashcat(21800)],
        _ => Vec::new(),
    }
}

impl Parse for Electrum {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$electrum$", 0)?;
        let fields =
            parse::split_fields(rest, '*', if rest.split('*').count() > 3 { 4 } else { 3 })?;
        let version = fields[0].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "invalid Electrum version",
            )
        })?;
        let (data, mac) = if fields.len() == 4 {
            (
                parse::decode_hex(fields[2].0, fields[2].1)?,
                parse::decode_hex(fields[3].0, fields[3].1)?,
            )
        } else {
            (parse::decode_hex(fields[2].0, fields[2].1)?, Vec::new())
        };
        Ok(Self {
            version,
            salt: fields[1].0.to_owned(),
            data,
            mac,
        })
    }
}

impl Render for Electrum {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        if self.mac.is_empty() {
            format!(
                "$electrum${}*{}*{}",
                self.version,
                self.salt,
                crate::format::hex(&self.data)
            )
        } else {
            format!(
                "$electrum${}*{}*{}*{}",
                self.version,
                self.salt,
                crate::format::hex(&self.data),
                crate::format::hex(&self.mac)
            )
        }
    }
}
