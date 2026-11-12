//! LUKS1 headers in the `$luks$1$` serialization.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// LUKS version 1 volume header.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "LUKS v1",
    slug = "luks-v1",
    hashcat = [29511, 29512, 29513, 29521, 29522, 29523, 29531, 29532, 29533, 29541, 29542, 29543],
    modes_fn = luks_v1_modes,
)]
pub struct LuksV1 {
    /// Password-hashing algorithm
    #[field(role = other, encoding = ascii)]
    pub hash: String,

    /// Bulk cipher
    #[field(role = other, encoding = ascii)]
    pub cipher: String,

    /// Cipher mode
    #[field(role = other, encoding = ascii)]
    pub cipher_mode: String,

    /// Key size in bits
    #[field(role = other, encoding = decimal)]
    pub key_bytes: u16,

    /// PBKDF2 iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// 32-byte PBKDF2 salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],

    /// Anti-forensic splitter data
    #[field(role = ciphertext, encoding = hex)]
    pub af: Vec<u8>,

    /// Encrypted master key
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: [u8; 512],
}

pub fn luks_v1_modes(value: &LuksV1) -> Vec<crate::Mode> {
    crate::types::luks_modes(&value.hash, &value.cipher)
}

impl Parse for LuksV1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$luks$1$", 0)?;
        let fields = parse::split_fields(rest, '$', 8)?;
        let hash = fields[0].0;
        let cipher = fields[1].0;
        if !matches!(hash, "sha1" | "sha256" | "sha512" | "ripemd160") {
            return Err(parse::error(
                crate::ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "unsupported LUKS v1 hash",
            ));
        }
        if !matches!(cipher, "aes" | "serpent" | "twofish") {
            return Err(parse::error(
                crate::ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "unsupported LUKS v1 cipher",
            ));
        }
        let cipher_mode = fields[2].0;
        if !matches!(
            cipher_mode,
            "cbc-essiv:sha256" | "cbc-plain" | "cbc-plain64" | "xts-plain" | "xts-plain64"
        ) {
            return Err(parse::error(
                crate::ParseErrorKind::InvalidCharacter,
                fields[2].1,
                "unsupported LUKS v1 cipher mode",
            ));
        }
        let key_bytes = fields[3].0.parse::<u16>().map_err(|_| {
            parse::error(
                crate::ParseErrorKind::InvalidCharacter,
                fields[3].1,
                "invalid LUKS v1 key size",
            )
        })?;
        if !matches!(key_bytes, 128 | 256 | 512) {
            return Err(parse::error(
                crate::ParseErrorKind::Other,
                fields[3].1,
                "LUKS v1 key size must be 128, 256, or 512",
            ));
        }
        let iterations = fields[4].0.parse::<u32>().map_err(|_| {
            parse::error(
                crate::ParseErrorKind::InvalidCharacter,
                fields[4].1,
                "invalid LUKS v1 iteration count",
            )
        })?;
        let af = parse::decode_hex(fields[6].0, fields[6].1)?;
        if !(64_000..=256_000).contains(&af.len()) {
            return Err(parse::error(
                crate::ParseErrorKind::InvalidLength,
                fields[6].1,
                "LUKS v1 anti-forensic data has an invalid length",
            ));
        }
        Ok(Self {
            hash: hash.to_owned(),
            cipher: cipher.to_owned(),
            cipher_mode: cipher_mode.to_owned(),
            key_bytes,
            iterations,
            salt: parse::decode_hex_field::<32>(fields[5].0, fields[5].1, "salt")?,
            af,
            ciphertext: parse::decode_hex_field::<512>(fields[7].0, fields[7].1, "ciphertext")?,
        })
    }
}

impl Render for LuksV1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$luks$1${}${}${}${}${}${}${}${}",
            self.hash,
            self.cipher,
            self.cipher_mode,
            self.key_bytes,
            self.iterations,
            crate::format::hex(self.salt),
            crate::format::hex(&self.af),
            crate::format::hex(self.ciphertext)
        )
    }
}
