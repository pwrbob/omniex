//! PKCS#8 private keys, rendered as a `$PEM$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PKCS#8 encrypted private keys.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PKCS#8 Private Keys",
    slug = "pem-private-key",
    hashcat = [24410, 24420],
    modes_fn = pem_private_key_modes,
)]
pub struct PemPrivateKey {
    /// KDF version, which selects the mode.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Cipher identifier.
    #[field(role = other, encoding = decimal)]
    pub cipher: u8,

    /// The 8-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// The 16-byte IV.
    #[field(role = iv, encoding = hex)]
    pub iv: [u8; 16],

    /// Key material length.
    #[field(role = other, encoding = decimal)]
    pub length: u32,

    /// Hexadecimal encrypted key material.
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

pub fn pem_private_key_modes(value: &PemPrivateKey) -> Vec<crate::Mode> {
    match value.version {
        1 => vec![crate::Mode::Hashcat(24410)],
        2 => vec![crate::Mode::Hashcat(24420)],
        _ => Vec::new(),
    }
}

impl Parse for PemPrivateKey {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$PEM$", 0)?;
        let fields = parse::split_fields(rest, '$', 7)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 5, "invalid PEM version")
            })?,
            cipher: fields[1].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid PEM cipher",
                )
            })?,
            salt: parse::decode_hex_field::<8>(fields[2].0, fields[2].1, "salt")?,
            iterations: fields[3].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[3].1,
                    "invalid PEM iteration count",
                )
            })?,
            iv: parse::decode_hex_field::<16>(fields[4].0, fields[4].1, "iv")?,
            length: fields[5].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[5].1,
                    "invalid PEM length",
                )
            })?,
            data: parse::decode_hex(fields[6].0, fields[6].1)?,
        })
    }
}

impl Render for PemPrivateKey {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$PEM${}${}${}${}${}${}${}",
            self.version,
            self.cipher,
            crate::format::hex(self.salt),
            self.iterations,
            crate::format::hex(self.iv),
            self.length,
            crate::format::hex(&self.data)
        )
    }
}
