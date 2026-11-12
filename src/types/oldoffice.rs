//! Microsoft Office documents from 2003 and earlier, rendered as
//! `$oldoffice$<version>*<salt>*<verifier>*<key>[:<rc4 key>]`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Microsoft Office <= 2003 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MS Office <= 2003",
    slug = "oldoffice",
    hashcat = [9700, 9710, 9720, 9800, 9810, 9820], john = ["oldoffice"],
    modes_fn = oldoffice_modes,
)]
pub struct OldOffice {
    /// Encryption version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// 16-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// 16-byte verifier
    #[field(role = other, encoding = hex)]
    pub verifier: [u8; 16],

    /// 16- or 20-byte key
    #[field(role = digest, encoding = hex)]
    pub key: Vec<u8>,

    /// Collider RC4 key (may be empty)
    #[field(role = key, encoding = hex)]
    pub rc4_key: Vec<u8>,

    /// Optional 32-byte Excel block
    #[field(role = other, encoding = hex)]
    pub second_block: Vec<u8>,
}

pub fn oldoffice_modes(value: &OldOffice) -> Vec<crate::Mode> {
    if value.rc4_key.is_empty() {
        match value.version {
            0 | 1 => vec![crate::Mode::Hashcat(9700), crate::Mode::Hashcat(9710)],
            3 | 4 => vec![crate::Mode::Hashcat(9800), crate::Mode::Hashcat(9810)],
            _ => Vec::new(),
        }
    } else {
        match value.version {
            0 | 1 => vec![crate::Mode::Hashcat(9720)],
            3 | 4 => vec![crate::Mode::Hashcat(9820)],
            _ => Vec::new(),
        }
    }
}

impl Parse for OldOffice {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$oldoffice$", 0)?;
        let mut fields = rest.splitn(5, '*');
        let version = fields.next().unwrap_or_default();
        let salt = fields.next().ok_or_else(|| {
            parse::error(ParseErrorKind::InvalidLength, 11, "missing Office salt")
        })?;
        let verifier = fields.next().ok_or_else(|| {
            parse::error(ParseErrorKind::InvalidLength, 11, "missing Office verifier")
        })?;
        let key = fields
            .next()
            .ok_or_else(|| parse::error(ParseErrorKind::InvalidLength, 11, "missing Office key"))?;
        let second_block = fields.next();

        let version = version
            .parse::<u8>()
            .map_err(|_| parse::error(ParseErrorKind::InvalidCharacter, 11, "invalid version"))?;
        let key_length = match version {
            0 | 1 => 16,
            3 | 4 => 20,
            _ => {
                return Err(parse::error(
                    ParseErrorKind::InvalidCharacter,
                    11,
                    "Office versions are 0, 1, 3, or 4",
                ));
            }
        };

        let (key, rc4_key) = match key.split_once(':') {
            Some((key, rc4_key)) => (key, Some(rc4_key)),
            None => (key, None),
        };
        let key_bytes = parse::decode_hex(key, 28)?;
        if key_bytes.len() != key_length {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                28,
                "Office key length does not match its version",
            ));
        }
        let rc4_key = match rc4_key {
            Some(value) => parse::decode_hex(value, 29 + key.len())?,
            None => Vec::new(),
        };
        let second_block = match second_block {
            Some(value) => parse::decode_hex(value, 30 + key.len())?,
            None => Vec::new(),
        };
        if !second_block.is_empty() && second_block.len() != 32 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                30 + key.len(),
                "Office second block is not 32 bytes",
            ));
        }

        Ok(Self {
            version,
            salt: parse::decode_hex_field::<16>(salt, 13, "salt")?,
            verifier: parse::decode_hex_field::<16>(verifier, 46, "verifier")?,
            key: key_bytes,
            rc4_key,
            second_block,
        })
    }
}

impl Render for OldOffice {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut value = format!(
            "$oldoffice${}*{}*{}*{}",
            self.version,
            crate::format::hex(self.salt),
            crate::format::hex(self.verifier),
            crate::format::hex(&self.key)
        );
        if !self.second_block.is_empty() {
            value.push('*');
            value.push_str(&crate::format::hex(&self.second_block));
        }
        if !self.rc4_key.is_empty() {
            value.push(':');
            value.push_str(&crate::format::hex(&self.rc4_key));
        }
        value
    }
}
