//! RC4 with key dropping, rendered as
//! `$rc4$<key bits>$<drop count>$<salt>$<pad>$<plaintext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// RC4 known-plaintext hashes with key dropping.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RC4 DropN",
    slug = "rc4-dropn",
    hashcat = [33500, 33501, 33502],
    modes_fn = rc4_dropn_modes,
)]
pub struct Rc4Dropn {
    /// Key size in bits
    #[field(role = other, encoding = decimal)]
    pub key_bits: u8,

    /// Key stream bytes to drop
    #[field(role = other, encoding = decimal)]
    pub drop_count: u8,

    /// Hexadecimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Padding marker, always `0`
    #[field(role = other, encoding = decimal)]
    pub pad: u8,

    /// Hexadecimal plaintext
    #[field(role = digest, encoding = ascii)]
    pub plaintext: String,
}

pub fn rc4_dropn_modes(value: &Rc4Dropn) -> Vec<crate::Mode> {
    match value.key_bits {
        40 => vec![crate::Mode::Hashcat(33500)],
        72 => vec![crate::Mode::Hashcat(33501)],
        104 => vec![crate::Mode::Hashcat(33502)],
        _ => Vec::new(),
    }
}

impl Parse for Rc4Dropn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$rc4$", 0)?;
        let fields = parse::split_fields(rest, '$', 5)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u8, ParseError> {
            value.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid RC4 {name}"),
                )
            })
        }
        Ok(Self {
            key_bits: number(fields[0].0, fields[0].1, "key bits")?,
            drop_count: number(fields[1].0, fields[1].1, "drop count")?,
            salt: fields[2].0.to_owned(),
            pad: number(fields[3].0, fields[3].1, "padding")?,
            plaintext: fields[4].0.to_owned(),
        })
    }
}

impl Render for Rc4Dropn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$rc4${}${}${}${}${}",
            self.key_bits, self.drop_count, self.salt, self.pad, self.plaintext
        )
    }
}
