//! AIX {ssha1}, rendered as `{ssha1}<exponent>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AIX ssha1 modular crypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "AIX {ssha1}",
    slug = "ssha1-aix",
    hashcat = [40017],
)]
pub struct AixSsha1 {
    /// Iteration count, encoded as a power-of-two exponent.
    #[field(role = iterations, encoding = decimal)]
    pub rounds: u32,

    /// Salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Twenty-seven digest characters.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for AixSsha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "{ssha1}", 0)?;
        if rest.len() < 3 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "AIX ssha1 value is too short",
            ));
        }

        let (exponent, rest) = rest.split_at(2);
        if !exponent.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                "ssha1".len() + 2,
                "invalid AIX iteration exponent",
            ));
        }
        let exponent = exponent.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                "ssha1".len() + 2,
                "invalid AIX iteration exponent",
            )
        })?;
        if exponent > 31 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                "ssha1".len() + 2,
                "AIX iteration exponent must be at most 31",
            ));
        }

        let rest = parse::strip_prefix(rest, "$", "ssha1".len() + 2)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', "ssha1".len() + 3)?;

        if !salt.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                "ssha1".len() + 3,
                "AIX salt must use the crypt alphabet",
            ));
        }
        if digest.len() != 27 || !digest.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                "ssha1".len() + 3 + digest_offset,
                "AIX ssha1 digest has the wrong length or alphabet",
            ));
        }

        Ok(Self {
            rounds: 1u32 << exponent,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for AixSsha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{{ssha1}}{:02}${}${}",
            self.rounds.trailing_zeros(),
            self.salt,
            self.digest
        )
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
