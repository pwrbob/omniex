//! Microsoft Office 2007 and later, rendered as
//! `$office$*<year>*<spin count>*<key size>*<salt size>*<salt>*<verifier>*<verifier hash>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Microsoft Office 2007, 2010, and 2013 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MS Office 2007/2010/2013",
    slug = "office",
    hashcat = [9400, 9500, 9600], john = ["Office"],
    modes_fn = office_modes,
)]
pub struct Office {
    /// Document year
    #[field(role = other, encoding = decimal)]
    pub year: u16,

    /// Password spin count
    #[field(role = iterations, encoding = decimal)]
    pub spin_count: u32,

    /// Derived key size in bits
    #[field(role = other, encoding = decimal)]
    pub key_size: u32,

    /// Salt size in bytes
    #[field(role = other, encoding = decimal)]
    pub salt_size: u32,

    /// Salt bytes
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Encrypted verifier
    #[field(role = ciphertext, encoding = hex)]
    pub verifier: Vec<u8>,

    /// Encrypted verifier hash
    #[field(role = digest, encoding = hex)]
    pub verifier_hash: Vec<u8>,
}

pub fn office_modes(value: &Office) -> Vec<crate::Mode> {
    match value.year {
        2007 => vec![crate::Mode::Hashcat(9400)],
        2010 => vec![crate::Mode::Hashcat(9500)],
        2013 => vec![crate::Mode::Hashcat(9600)],
        _ => Vec::new(),
    }
}

impl Parse for Office {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$office$*", 0)?;
        let fields = parse::split_fields(rest, '*', 7)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u32, ParseError> {
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid Office {name}"),
                )
            })
        }

        let year = number(fields[0].0, fields[0].1, "year")?;
        let spin_count = number(fields[1].0, fields[1].1, "spin count")?;
        let key_size = number(fields[2].0, fields[2].1, "key size")?;
        let salt_size = number(fields[3].0, fields[3].1, "salt size")?;
        let salt = parse::decode_hex(fields[4].0, fields[4].1)?;
        if salt.len() != salt_size as usize {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[4].1,
                "Office salt length does not match its header",
            ));
        }
        let expected_hash = match year {
            2007 => 20,
            2010 | 2013 => 32,
            _ => {
                return Err(parse::error(
                    ParseErrorKind::InvalidCharacter,
                    9,
                    "Office years are 2007, 2010, or 2013",
                ));
            }
        };
        let verifier_hash = parse::decode_hex(fields[6].0, fields[6].1)?;
        if verifier_hash.len() != expected_hash {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[6].1,
                "Office verifier hash length does not match its year",
            ));
        }

        Ok(Self {
            year: u16::try_from(year).map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 9, "invalid Office year")
            })?,
            spin_count,
            key_size,
            salt_size,
            salt,
            verifier: parse::decode_hex(fields[5].0, fields[5].1)?,
            verifier_hash,
        })
    }
}

impl Render for Office {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$office$*{}*{}*{}*{}*{}*{}*{}",
            self.year,
            self.spin_count,
            self.key_size,
            self.salt_size,
            crate::format::hex(&self.salt),
            crate::format::hex(&self.verifier),
            crate::format::hex(&self.verifier_hash)
        )
    }
}
