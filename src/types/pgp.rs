//! OpenPGP passphrase hashes, rendered as either
//! `$gpg$*<version>*<encrypted size>*<key size>*<encrypted data>*<s2k fields>*<cipher>*<iv size>*<iv>*<iterations>*<salt>`
//! for secret keys or
//! `$gpg$*0*<encrypted size>*<encrypted data>*<s2k fields>*<cipher>*<iterations>*<salt>`
//! for symmetrically encrypted files.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// OpenPGP passphrase hashes for secret keys and symmetrically encrypted files.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "OpenPGP",
    slug = "pgp",
    hashcat = [17010, 17020, 17030, 17040, 17050], john = ["gpg"],
    modes_fn = pgp_modes,
)]
pub struct Pgp {
    /// Public-key algorithm
    #[field(role = other, encoding = decimal)]
    pub algorithm: u8,

    /// Encrypted data size (bytes)
    #[field(role = other, encoding = decimal)]
    pub encrypted_size: u32,

    /// Modulus bits (0 if symmetric)
    #[field(role = other, encoding = decimal)]
    pub modulus_size: u32,

    /// Encrypted key packet
    #[field(role = ciphertext, encoding = hex)]
    pub encrypted_data: Vec<u8>,

    /// String-to-key type (`3`)
    #[field(role = other, encoding = decimal)]
    pub s2k_type: u8,

    /// String-to-key usage
    #[field(role = other, encoding = decimal)]
    pub s2k_mode: u8,

    /// String-to-key hash
    #[field(role = other, encoding = decimal)]
    pub s2k_hash: u32,

    /// Cipher algorithm identifier
    #[field(role = other, encoding = decimal)]
    pub cipher: u8,

    /// IV size (0 if symmetric)
    #[field(role = other, encoding = decimal)]
    pub iv_size: u8,

    /// IV (empty if symmetric)
    #[field(role = other, encoding = hex)]
    pub iv: Vec<u8>,

    /// String-to-key iterations
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// 8-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,
}

pub fn pgp_modes(value: &Pgp) -> Vec<crate::Mode> {
    use crate::Mode;

    let john = || vec![Mode::John("gpg")];
    if value.algorithm == 0 {
        return john();
    }
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

impl Parse for Pgp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$gpg$*", 0)?;
        let fields = match rest.split('*').count() {
            9 => parse::split_fields(rest, '*', 9)?,
            12 => parse::split_fields(rest, '*', 12)?,
            _ => {
                return Err(parse::error(
                    ParseErrorKind::InvalidLength,
                    input.len(),
                    "expected 9 or 12 GPG fields",
                ));
            }
        };
        fn number(value: &str, offset: usize, name: &str) -> Result<u32, ParseError> {
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid GPG {name}"),
                )
            })
        }

        let symmetric = fields.len() == 9;
        let data = if symmetric { 2 } else { 3 };
        let encrypted_data = parse::decode_hex(fields[data].0, fields[data].1)?;
        if encrypted_data.len() != number(fields[1].0, fields[1].1, "encrypted size")? as usize {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[data].1,
                "GPG encrypted data length does not match its header",
            ));
        }

        let algorithm =
            u8::try_from(number(fields[0].0, fields[0].1, "algorithm")?).map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 6, "invalid GPG algorithm")
            })?;
        if symmetric && algorithm != 0 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "GPG secret-key hash is missing fields",
            ));
        }
        let (modulus_size, iv_size, iv) = if symmetric {
            (0, 0, Vec::new())
        } else {
            (
                number(fields[2].0, fields[2].1, "modulus size")?,
                u8::try_from(number(fields[8].0, fields[8].1, "iv size")?).map_err(|_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[8].1,
                        "invalid iv size",
                    )
                })?,
                parse::decode_hex(fields[9].0, fields[9].1)?,
            )
        };
        let s2k = if symmetric { 3 } else { 4 };
        let cipher = s2k + 3;
        let tail = if symmetric { s2k + 4 } else { s2k + 6 };

        Ok(Self {
            algorithm,
            encrypted_size: number(fields[1].0, fields[1].1, "encrypted size")?,
            modulus_size,
            encrypted_data,
            s2k_type: u8::try_from(number(fields[s2k].0, fields[s2k].1, "s2k type")?).map_err(
                |_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[s2k].1,
                        "invalid s2k type",
                    )
                },
            )?,
            s2k_mode: u8::try_from(number(fields[s2k + 1].0, fields[s2k + 1].1, "s2k mode")?)
                .map_err(|_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[s2k + 1].1,
                        "invalid s2k mode",
                    )
                })?,
            s2k_hash: number(fields[s2k + 2].0, fields[s2k + 2].1, "s2k hash")?,
            cipher: u8::try_from(number(fields[cipher].0, fields[cipher].1, "cipher")?).map_err(
                |_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[cipher].1,
                        "invalid cipher",
                    )
                },
            )?,
            iv_size,
            iv,
            iterations: number(fields[tail].0, fields[tail].1, "iterations")?,
            salt: parse::decode_hex(fields[tail + 1].0, fields[tail + 1].1)?,
        })
    }
}

impl Render for Pgp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        if self.algorithm == 0 {
            return format!(
                "$gpg$*0*{}*{}*{}*{}*{}*{}*{}*{}",
                self.encrypted_size,
                crate::format::hex(&self.encrypted_data),
                self.s2k_type,
                self.s2k_mode,
                self.s2k_hash,
                self.cipher,
                self.iterations,
                crate::format::hex(&self.salt)
            );
        }
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
