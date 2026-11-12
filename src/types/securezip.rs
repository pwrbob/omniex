//! SecureZIP AES hashes, rendered as a `$zip3$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SecureZIP AES hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SecureZIP AES",
    slug = "securezip",
    hashcat = [23001, 23002, 23003], john = ["securezip"],
    modes_fn = securezip_modes,
)]
pub struct Securezip {
    /// Archive version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Entry type
    #[field(role = other, encoding = decimal)]
    pub kind: u8,

    /// AES key size in bits
    #[field(role = other, encoding = decimal)]
    pub key_bits: u16,

    /// Unused field
    #[field(role = other, encoding = ascii)]
    pub unused: String,

    /// Initialization vector
    #[field(role = salt, encoding = ascii)]
    pub iv: String,

    /// Encrypted data
    #[field(role = ciphertext, encoding = ascii)]
    pub data: String,

    /// Flags and file name
    #[field(role = other, encoding = ascii)]
    pub rest: String,
}

pub fn securezip_modes(value: &Securezip) -> Vec<crate::Mode> {
    match value.key_bits {
        128 => vec![crate::Mode::Hashcat(23001)],
        192 => vec![crate::Mode::Hashcat(23002)],
        256 => vec![crate::Mode::Hashcat(23003)],
        _ => Vec::new(),
    }
}

impl Parse for Securezip {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$zip3$*", 0)?;
        let parts = rest.split('*').collect::<Vec<_>>();
        if parts.len() < 10 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                rest.len(),
                "SecureZIP hashes have at least ten fields",
            ));
        }
        Ok(Self {
            version: parts[0].parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    7,
                    "invalid SecureZIP version",
                )
            })?,
            kind: parts[1].parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    9,
                    "invalid SecureZIP type",
                )
            })?,
            key_bits: parts[2].parse::<u16>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    11,
                    "invalid SecureZIP key size",
                )
            })?,
            unused: parts[3].to_owned(),
            iv: parts[4].to_owned(),
            data: parts[5].to_owned(),
            rest: parts[6..].join("*"),
        })
    }
}

impl Render for Securezip {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$zip3$*{}*{}*{}*{}*{}*{}*{}",
            self.version, self.kind, self.key_bits, self.unused, self.iv, self.data, self.rest
        )
    }
}
