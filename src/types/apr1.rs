//! Apache `$apr1$` MD5, rendered as modular crypt.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Apache `$apr1$` MD5 password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Apache MD5 (apr1)",
    slug = "apr1",
    hashcat = [1600],
    john = ["md5crypt"],
    modes_fn = apr1_modes,
)]
pub struct Apr1 {
    /// Explicit round count, or zero for the default.
    #[field(role = iterations, encoding = decimal)]
    pub rounds: u32,

    /// Up to eight salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Twenty-two digest characters.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

pub fn apr1_modes(value: &Apr1) -> Vec<crate::Mode> {
    if value.salt.len() > 8 {
        return Vec::new();
    }

    Apr1::DESCRIPTOR.all_modes.to_vec()
}

impl Parse for Apr1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$apr1$", 0)?;

        let (rounds, rest, base) = if let Some(after_rounds) = rest.strip_prefix("rounds=") {
            let (rounds, rest, next) = parse::split_once(after_rounds, '$', 10)?;
            let rounds = rounds.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    10,
                    "invalid apr1 round count",
                )
            })?;
            (rounds, rest, next)
        } else {
            (0, rest, 6)
        };

        let (salt, digest, digest_offset) = parse::split_once(rest, '$', base)?;

        if salt.len() > 8 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                base,
                "apr1 salt must contain at most 8 characters",
            ));
        }
        if !salt.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                base,
                "apr1 salt must use the crypt alphabet",
            ));
        }
        if digest.len() != 22 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "apr1 digest must be 22 characters",
            ));
        }
        if !digest.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                digest_offset,
                "apr1 digest must use the crypt alphabet",
            ));
        }

        Ok(Self {
            rounds,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Apr1 {
    fn render(&self, _opts: &RenderOptions) -> String {
        if self.rounds == 0 {
            format!("$apr1${}${}", self.salt, self.digest)
        } else {
            format!(
                "$apr1$rounds=${}${}${}",
                self.rounds, self.salt, self.digest
            )
        }
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
