//! VirtualBox, rendered as a `$vbox$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// VirtualBox disk encryption hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "VirtualBox",
    slug = "virtualbox",
    hashcat = [27500, 27600],
    modes_fn = virtualbox_modes,
)]
pub struct Virtualbox {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// First derivation iterations
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// 32-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],

    /// XTS key size in bytes
    #[field(role = other, encoding = decimal)]
    pub key_size: u8,

    /// Ciphertext
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,

    /// Second derivation iterations
    #[field(role = iterations, encoding = decimal)]
    pub second_iterations: u32,

    /// Second 32-byte salt
    #[field(role = salt, encoding = hex)]
    pub second_salt: [u8; 32],

    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

pub fn virtualbox_modes(value: &Virtualbox) -> Vec<crate::Mode> {
    match value.key_size {
        8 => vec![crate::Mode::Hashcat(27500)],
        16 => vec![crate::Mode::Hashcat(27600)],
        _ => Vec::new(),
    }
}

impl Parse for Virtualbox {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$vbox$", 0)?;
        let fields = parse::split_fields(rest, '$', 8)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    6,
                    "invalid VirtualBox version",
                )
            })?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid VirtualBox iteration count",
                )
            })?,
            salt: parse::decode_hex_field::<32>(fields[2].0, fields[2].1, "salt")?,
            key_size: fields[3].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[3].1,
                    "invalid VirtualBox key size",
                )
            })?,
            ciphertext: parse::decode_hex(fields[4].0, fields[4].1)?,
            second_iterations: fields[5].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[5].1,
                    "invalid VirtualBox second iteration count",
                )
            })?,
            second_salt: parse::decode_hex_field::<32>(fields[6].0, fields[6].1, "second salt")?,
            digest: parse::decode_hex_field::<32>(fields[7].0, fields[7].1, "digest")?,
        })
    }
}

impl Render for Virtualbox {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$vbox${}${}${}${}${}${}${}${}",
            self.version,
            self.iterations,
            crate::format::hex(self.salt),
            self.key_size,
            crate::format::hex(&self.ciphertext),
            self.second_iterations,
            crate::format::hex(self.second_salt),
            crate::format::hex(self.digest)
        )
    }
}
