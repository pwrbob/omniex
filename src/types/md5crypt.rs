//! md5crypt (`$1$`), rendered as modular crypt.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// md5crypt password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "md5crypt",
    slug = "md5crypt",
    hashcat = [500],
    john = ["md5crypt"],
)]
pub struct Md5Crypt {
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

impl Parse for Md5Crypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$1$", 0)?;

        let (rounds, rest, base) = if let Some(after_rounds) = rest.strip_prefix("rounds=") {
            let (rounds, rest, next) = parse::split_once(after_rounds, '$', 10)?;
            let rounds = rounds.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    10,
                    "invalid md5crypt round count",
                )
            })?;
            (rounds, rest, next)
        } else {
            (0, rest, 3)
        };

        let (salt, digest, digest_offset) = parse::split_once(rest, '$', base)?;

        if salt.is_empty() || salt.len() > 8 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                base,
                "md5crypt salt must contain 1 to 8 characters",
            ));
        }
        if !salt.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                base,
                "md5crypt salt must use the crypt alphabet",
            ));
        }
        if digest.len() != 22 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "md5crypt digest must be 22 characters",
            ));
        }
        if !digest.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                digest_offset,
                "md5crypt digest must use the crypt alphabet",
            ));
        }

        Ok(Self {
            rounds,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Md5Crypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        if self.rounds == 0 {
            format!("$1${}${}", self.salt, self.digest)
        } else {
            format!("$1$rounds=${}${}${}", self.rounds, self.salt, self.digest)
        }
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
