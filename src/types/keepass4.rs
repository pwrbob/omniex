//! KeePass KDBX v4 hashes, rendered as
//! `$keepass$*4*<iterations>*<kdf uuid>*<memory>*<kdf version>*<parallelism>*<master seed>*<salt>*<header>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// KeePass KDBX v4 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "KeePass KDBX v4",
    slug = "keepass4",
    hashcat = [34300, 34301], john = ["KeePass"],
    modes_fn = keepass4_modes,
)]
pub struct Keepass4 {
    /// Database version (`4`)
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// KDF iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// KDF UUID
    #[field(role = other, encoding = ascii)]
    pub kdf_uuid: String,

    /// Memory usage in bytes
    #[field(role = other, encoding = decimal)]
    pub memory: u64,

    /// KDF format version
    #[field(role = other, encoding = decimal)]
    pub kdf_version: u8,

    /// Argon2 lanes / AES-KDF param
    #[field(role = other, encoding = decimal)]
    pub parallelism: u8,

    /// Hexadecimal master seed
    #[field(role = salt, encoding = ascii)]
    pub master_seed: String,

    /// KDF salt (hex)
    #[field(role = other, encoding = ascii)]
    pub salt: String,

    /// Hexadecimal header bytes
    #[field(role = other, encoding = ascii)]
    pub header: String,

    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Optional keyfile fields
    #[field(role = other, encoding = ascii)]
    pub keyfile: String,
}

pub fn keepass4_modes(value: &Keepass4) -> Vec<crate::Mode> {
    let mut modes = if value.kdf_uuid.starts_with("c9d9f39a") {
        vec![crate::Mode::Hashcat(34301)]
    } else {
        vec![crate::Mode::Hashcat(34300)]
    };
    modes.push(crate::Mode::John("KeePass"));
    modes
}

impl Parse for Keepass4 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$keepass$*", 0)?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() < 10 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                rest.len(),
                "KeePass v4 hashes have at least ten fields",
            ));
        }
        let version = parts[0].parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "invalid KeePass version",
            )
        })?;
        if version != 4 {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "this type supports KeePass version 4 only",
            ));
        }
        fn number(value: &str, offset: usize, name: &str) -> Result<u64, ParseError> {
            value.parse::<u64>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid KeePass {name}"),
                )
            })
        }
        fn small(value: &str, offset: usize, name: &str) -> Result<u8, ParseError> {
            u8::try_from(number(value, offset, name)?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid KeePass {name}"),
                )
            })
        }

        let keyfile = parts[10..].join("*");

        Ok(Self {
            version,
            iterations: u32::try_from(number(parts[1], 10, "iterations")?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    10,
                    "invalid KeePass iteration count",
                )
            })?,
            kdf_uuid: parts[2].to_owned(),
            memory: number(parts[3], 10, "memory")?,
            kdf_version: small(parts[4], 10, "KDF version")?,
            parallelism: small(parts[5], 10, "parallelism")?,
            master_seed: parts[6].to_owned(),
            salt: parts[7].to_owned(),
            header: parts[8].to_owned(),
            digest: parse::decode_hex_field::<32>(parts[9], 10, "digest")?,
            keyfile,
        })
    }
}

impl Render for Keepass4 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut value = format!(
            "$keepass$*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}",
            self.version,
            self.iterations,
            self.kdf_uuid,
            self.memory,
            self.kdf_version,
            self.parallelism,
            self.master_seed,
            self.salt,
            self.header,
            crate::format::hex(self.digest)
        );
        if !self.keyfile.is_empty() {
            value.push('*');
            value.push_str(&self.keyfile);
        }
        value
    }
}
