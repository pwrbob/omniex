//! GnuPG secret-key passphrase hashes, rendered as
//! `$gpg$*<version>*<encrypted size>*<key size>*<encrypted data>*<s2k fields>*<cipher>*<iv size>*<iv>*<iterations>*<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// GnuPG secret-key passphrase hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "GPG",
    slug = "gpg",
    hashcat = [17010, 17020, 17030, 17040, 17050], john = ["gpg"],
    modes_fn = gpg_modes,
)]
pub struct Gpg {
    /// Public-key algorithm identifier.
    #[field(role = other, encoding = decimal)]
    pub algorithm: u8,

    /// Encrypted data size in bytes.
    #[field(role = other, encoding = decimal)]
    pub encrypted_size: u32,

    /// Modulus size in bits.
    #[field(role = other, encoding = decimal)]
    pub modulus_size: u32,

    /// Encrypted key packet.
    #[field(role = ciphertext, encoding = hex)]
    pub encrypted_data: Vec<u8>,

    /// String-to-key type, always `3`.
    #[field(role = other, encoding = decimal)]
    pub s2k_type: u8,

    /// String-to-key usage identifier.
    #[field(role = other, encoding = decimal)]
    pub s2k_mode: u8,

    /// String-to-key hash identifier.
    #[field(role = other, encoding = decimal)]
    pub s2k_hash: u32,

    /// Cipher algorithm identifier.
    #[field(role = other, encoding = decimal)]
    pub cipher: u8,

    /// Initialization vector size in bytes.
    #[field(role = other, encoding = decimal)]
    pub iv_size: u8,

    /// Initialization vector.
    #[field(role = other, encoding = hex)]
    pub iv: Vec<u8>,

    /// String-to-key iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Eight or twelve-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,
}

pub fn gpg_modes(value: &Gpg) -> Vec<crate::Mode> {
    use crate::Mode;

    let john = || vec![Mode::John("gpg")];
    match (value.cipher, value.s2k_hash) {
        (3, 2) => {
            let mut modes = vec![Mode::Hashcat(17040)];
            modes.extend(john());
            modes
        }
        (7 | 9, 2) if value.iv.len() == 12 => vec![Mode::Hashcat(17050)],
        (7 | 9, 2) if matches!(value.algorithm, 1..=3) => {
            let mut modes = vec![Mode::Hashcat(17010)];
            modes.extend(john());
            modes
        }
        (7 | 9, 10) if matches!(value.algorithm, 1..=3) => {
            let mut modes = vec![Mode::Hashcat(17020)];
            modes.extend(john());
            modes
        }
        (7 | 9, 8) if matches!(value.algorithm, 1..=3) => {
            let mut modes = vec![Mode::Hashcat(17030)];
            modes.extend(john());
            modes
        }
        (3 | 7 | 9, 2 | 8 | 10) => john(),
        _ => Vec::new(),
    }
}

impl Parse for Gpg {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$gpg$*", 0)?;
        let fields = parse::split_fields(rest, '*', 12)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u32, ParseError> {
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid GPG {name}"),
                )
            })
        }

        let encrypted_data = parse::decode_hex(fields[3].0, fields[3].1)?;
        if encrypted_data.len() != number(fields[1].0, fields[1].1, "encrypted size")? as usize {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[3].1,
                "GPG encrypted data length does not match its header",
            ));
        }

        Ok(Self {
            algorithm: u8::try_from(number(fields[0].0, fields[0].1, "algorithm")?).map_err(
                |_| parse::error(ParseErrorKind::InvalidCharacter, 6, "invalid GPG algorithm"),
            )?,
            encrypted_size: number(fields[1].0, fields[1].1, "encrypted size")?,
            modulus_size: number(fields[2].0, fields[2].1, "modulus size")?,
            encrypted_data,
            s2k_type: u8::try_from(number(fields[4].0, fields[4].1, "s2k type")?).map_err(
                |_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[4].1,
                        "invalid s2k type",
                    )
                },
            )?,
            s2k_mode: u8::try_from(number(fields[5].0, fields[5].1, "s2k mode")?).map_err(
                |_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[5].1,
                        "invalid s2k mode",
                    )
                },
            )?,
            s2k_hash: number(fields[6].0, fields[6].1, "s2k hash")?,
            cipher: u8::try_from(number(fields[7].0, fields[7].1, "cipher")?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[7].1,
                    "invalid cipher",
                )
            })?,
            iv_size: u8::try_from(number(fields[8].0, fields[8].1, "iv size")?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[8].1,
                    "invalid iv size",
                )
            })?,
            iv: parse::decode_hex(fields[9].0, fields[9].1)?,
            iterations: number(fields[10].0, fields[10].1, "iterations")?,
            salt: parse::decode_hex(fields[11].0, fields[11].1)?,
        })
    }
}

impl Render for Gpg {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$gpg$*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}",
            self.algorithm,
            self.encrypted_size,
            self.modulus_size,
            crate::format::hex(&self.encrypted_data),
            self.s2k_type,
            self.s2k_mode,
            self.s2k_hash,
            self.cipher,
            self.iv_size,
            crate::format::hex(&self.iv),
            self.iterations,
            crate::format::hex(&self.salt)
        )
    }
}
