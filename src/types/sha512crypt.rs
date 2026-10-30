//! sha512crypt (`$6$`), rendered as modular crypt.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// sha512crypt password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "sha512crypt",
    slug = "sha512crypt",
    hashcat = [1800],
    john = ["sha512crypt"],
)]
pub struct Sha512Crypt {
    /// Explicit round count, or zero for the default.
    #[field(role = iterations, encoding = decimal)]
    pub rounds: u32,

    /// Up to sixteen salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Eighty-six digest characters.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Sha512Crypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$6$", 0)?;

        let (rounds, rest, base) = if let Some(after_rounds) = rest.strip_prefix("rounds=") {
            let (rounds, rest, next) = parse::split_once(after_rounds, '$', 9)?;
            let rounds = rounds.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    9,
                    "invalid sha512crypt round count",
                )
            })?;
            (rounds, rest, next)
        } else {
            (0, rest, 3)
        };

        let (salt, digest, digest_offset) = parse::split_once(rest, '$', base)?;

        if salt.len() > 16 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                base,
                "sha512crypt salt must contain at most 16 characters",
            ));
        }
        if !salt.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                base,
                "sha512crypt salt must use the crypt alphabet",
            ));
        }
        if digest.len() != 86 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "sha512crypt digest must be 86 characters",
            ));
        }
        if !digest.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                digest_offset,
                "sha512crypt digest must use the crypt alphabet",
            ));
        }

        Ok(Self {
            rounds,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Sha512Crypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        if self.rounds == 0 {
            format!("$6${}${}", self.salt, self.digest)
        } else {
            format!("$6$rounds=${}${}${}", self.rounds, self.salt, self.digest)
        }
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
