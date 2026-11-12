//! LUKS2 headers in the `$luks$2$` Argon2 serialization.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// LUKS version 2 volume header using Argon2.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "LUKS v2 Argon2",
    slug = "luks-v2",
    hashcat = [34100],
)]
pub struct LuksV2 {
    /// Argon2 variant
    #[field(role = other, encoding = ascii)]
    pub kdf: String,

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

    /// Argon2 memory cost in KiB
    #[field(role = other, encoding = decimal)]
    pub memory: u32,

    /// Argon2 iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Argon2 parallelism
    #[field(role = other, encoding = decimal)]
    pub parallelism: u32,

    /// 32-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],

    /// Anti-forensic splitter data
    #[field(role = ciphertext, encoding = hex)]
    pub af: Vec<u8>,

    /// Encrypted master key
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: [u8; 512],
}

impl Parse for LuksV2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$luks$2$", 0)?;
        let fields = parse::split_fields(rest, '$', 9)?;
        let kdf = fields[0].0;
        if !matches!(kdf, "argon2i" | "argon2id") {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "unsupported LUKS v2 Argon2 variant",
            ));
        }
        if fields[1].0 != "sha256" || fields[2].0 != "aes" {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "LUKS v2 supports SHA-256 and AES",
            ));
        }
        let cipher_mode = fields[3].0;
        if !matches!(
            cipher_mode,
            "cbc-essiv:sha256" | "cbc-plain" | "cbc-plain64" | "xts-plain" | "xts-plain64"
        ) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[3].1,
                "unsupported LUKS v2 cipher mode",
            ));
        }
        let number = |field: (&str, usize), name: &str| {
            field.0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("invalid LUKS v2 {name}"),
                )
            })
        };
        let key_bytes = number(fields[4], "key size")? as u16;
        if !matches!(key_bytes, 128 | 256 | 512) {
            return Err(parse::error(
                ParseErrorKind::Other,
                fields[4].1,
                "LUKS v2 key size must be 128, 256, or 512",
            ));
        }
        let params = parse::split_fields(fields[5].0, ',', 3)?;
        let parameter = |field: (&str, usize), prefix: &str, name: &str| {
            let value = field.0.strip_prefix(prefix).ok_or_else(|| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("expected LUKS v2 {name} prefix `{prefix}`"),
                )
            })?;
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1 + prefix.len(),
                    format!("invalid LUKS v2 {name}"),
                )
            })
        };
        let af = parse::decode_hex(fields[7].0, fields[7].1)?;
        if !(64_000..=256_000).contains(&af.len()) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[7].1,
                "LUKS v2 anti-forensic data has an invalid length",
            ));
        }
        Ok(Self {
            kdf: kdf.to_owned(),
            hash: fields[1].0.to_owned(),
            cipher: fields[2].0.to_owned(),
            cipher_mode: cipher_mode.to_owned(),
            key_bytes,
            memory: parameter(params[0], "m=", "memory cost")?,
            iterations: parameter(params[1], "t=", "iteration count")?,
            parallelism: parameter(params[2], "p=", "parallelism")?,
            salt: parse::decode_hex_field::<32>(fields[6].0, fields[6].1, "salt")?,
            af,
            ciphertext: parse::decode_hex_field::<512>(fields[8].0, fields[8].1, "ciphertext")?,
        })
    }
}

impl Render for LuksV2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$luks$2${}${}${}${}${}$m={},t={},p={}${}${}${}",
            self.kdf,
            self.hash,
            self.cipher,
            self.cipher_mode,
            self.key_bytes,
            self.memory,
            self.iterations,
            self.parallelism,
            crate::format::hex(self.salt),
            crate::format::hex(&self.af),
            crate::format::hex(self.ciphertext)
        )
    }
}
