//! KeePass KDBX v1 and v2 hashes, rendered as
//! `$keepass$*<version>*<rounds>*<algorithm>*<seed>*<transform seed>*<iv>*<details>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// KeePass KDBX v1 and v2 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "KeePass (KDBX v2/v3)",
    slug = "keepass",
    hashcat = [13400, 29700],
    modes_fn = keepass_modes,
)]
pub struct Keepass {
    /// Database format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// AES key derivation round count.
    #[field(role = iterations, encoding = decimal)]
    pub rounds: u64,

    /// Cipher algorithm identifier.
    #[field(role = other, encoding = decimal)]
    pub algorithm: u8,

    /// Hexadecimal master seed.
    #[field(role = salt, encoding = ascii)]
    pub seed: String,

    /// Hexadecimal transform seed.
    #[field(role = other, encoding = ascii)]
    pub transform_seed: String,

    /// Hexadecimal initialization vector.
    #[field(role = other, encoding = ascii)]
    pub iv: String,

    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub details: String,
}

pub fn keepass_modes(value: &Keepass) -> Vec<crate::Mode> {
    match value.version {
        1 | 2 => vec![crate::Mode::Hashcat(13400), crate::Mode::Hashcat(29700)],
        _ => Vec::new(),
    }
}

impl Parse for Keepass {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$keepass$*", 0)?;
        let fields: Vec<&str> = rest.split('*').collect();
        if fields.len() < 7 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                rest.len(),
                "KeePass hashes have at least seven fields",
            ));
        }
        let version = fields[0].parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "invalid KeePass version",
            )
        })?;
        if !matches!(version, 1 | 2) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "this type supports KeePass versions 1 and 2",
            ));
        }
        let rounds = fields[1].parse::<u64>().map_err(|_| {
            parse::error(ParseErrorKind::InvalidCharacter, 10, "invalid round count")
        })?;
        let algorithm = fields[2].parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "invalid KeePass algorithm",
            )
        })?;

        Ok(Self {
            version,
            rounds,
            algorithm,
            seed: fields[3].to_owned(),
            transform_seed: fields[4].to_owned(),
            iv: fields[5].to_owned(),
            details: fields[6..].join("*"),
        })
    }
}

impl Render for Keepass {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut value = format!(
            "$keepass$*{}*{}*{}*{}*{}*{}",
            self.version, self.rounds, self.algorithm, self.seed, self.transform_seed, self.iv
        );
        if !self.details.is_empty() {
            value.push('*');
            value.push_str(&self.details);
        }
        value
    }
}
