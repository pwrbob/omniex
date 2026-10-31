//! Open Document Format hashes, rendered as
//! `$odf$*<cipher>*<checksum type>*<iterations>*<key size>*<checksum>*<iv size>*<iv>*<salt size>*<salt>*<unused>*<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Open Document Format hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Open Document Format",
    slug = "odf",
    hashcat = [18400, 18600],
    modes_fn = odf_modes,
)]
pub struct Odf {
    /// Cipher type, `0` for Blowfish and `1` for AES.
    #[field(role = other, encoding = decimal)]
    pub cipher_type: u8,

    /// Checksum type, always `0`.
    #[field(role = other, encoding = decimal)]
    pub checksum_type: u8,

    /// Key derivation iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Key size in bits.
    #[field(role = other, encoding = decimal)]
    pub key_size: u32,

    /// Hexadecimal checksum.
    #[field(role = digest, encoding = ascii)]
    pub checksum: String,

    /// Initialization vector size in bytes.
    #[field(role = other, encoding = decimal)]
    pub iv_size: u8,

    /// Hexadecimal initialization vector.
    #[field(role = other, encoding = ascii)]
    pub iv: String,

    /// Salt size in bytes.
    #[field(role = other, encoding = decimal)]
    pub salt_size: u8,

    /// Hexadecimal salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Unused field, always `0`.
    #[field(role = other, encoding = decimal)]
    pub unused: u8,

    /// Encrypted data.
    #[field(role = ciphertext, encoding = ascii)]
    pub data: String,
}

pub fn odf_modes(value: &Odf) -> Vec<crate::Mode> {
    match value.cipher_type {
        0 => vec![crate::Mode::Hashcat(18600)],
        1 => vec![crate::Mode::Hashcat(18400)],
        _ => Vec::new(),
    }
}

impl Parse for Odf {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$odf$*", 0)?;
        let fields = parse::split_fields(rest, '*', 11)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u32, ParseError> {
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid ODF {name}"),
                )
            })
        }
        fn small(value: &str, offset: usize, name: &str) -> Result<u8, ParseError> {
            u8::try_from(number(value, offset, name)?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid ODF {name}"),
                )
            })
        }

        Ok(Self {
            cipher_type: small(fields[0].0, fields[0].1, "cipher type")?,
            checksum_type: small(fields[1].0, fields[1].1, "checksum type")?,
            iterations: number(fields[2].0, fields[2].1, "iterations")?,
            key_size: number(fields[3].0, fields[3].1, "key size")?,
            checksum: fields[4].0.to_owned(),
            iv_size: small(fields[5].0, fields[5].1, "iv size")?,
            iv: fields[6].0.to_owned(),
            salt_size: small(fields[7].0, fields[7].1, "salt size")?,
            salt: fields[8].0.to_owned(),
            unused: small(fields[9].0, fields[9].1, "unused")?,
            data: fields[10].0.to_owned(),
        })
    }
}

impl Render for Odf {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$odf$*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}",
            self.cipher_type,
            self.checksum_type,
            self.iterations,
            self.key_size,
            self.checksum,
            self.iv_size,
            self.iv,
            self.salt_size,
            self.salt,
            self.unused,
            self.data
        )
    }
}
