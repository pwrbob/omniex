//! phpass (`$P$`/`$H$`), rendered as modular crypt.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// phpass portable hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "phpass",
    slug = "phpass",
    hashcat = [400],
    john = ["phpass"],
)]
pub struct Phpass {
    /// Hash signature, `$P$` or `$H$`.
    #[field(role = other, encoding = ascii)]
    pub prefix: String,

    /// Base-2 logarithm of the iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Eight-character salt from the phpass alphabet.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Twenty-two-character digest from the phpass alphabet.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Phpass {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let prefix = if input.starts_with("$P$") {
            "$P$"
        } else if input.starts_with("$H$") {
            "$H$"
        } else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected `$P$` or `$H$` prefix",
            ));
        };

        let body = &input[3..];
        if body.len() != 31 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                3,
                "phpass body must contain a setting, 8 salt bytes, and 22 digest bytes",
            ));
        }

        let setting = body.as_bytes()[0];
        let iterations = itoa64_index(setting).ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                3,
                "invalid phpass cost character",
            )
        })?;

        let salt = &body[1..9];
        let digest = &body[9..31];

        if !salt.bytes().all(|byte| itoa64_index(byte).is_some())
            || !digest.bytes().all(|byte| itoa64_index(byte).is_some())
        {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                4,
                "phpass salt and digest must use the phpass alphabet",
            ));
        }

        Ok(Self {
            prefix: prefix.to_owned(),
            iterations,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Phpass {
    fn render(&self, _opts: &RenderOptions) -> String {
        let setting = ITOA64
            .get(self.iterations as usize)
            .copied()
            .unwrap_or(b'.') as char;

        format!("{}{setting}{}{}", self.prefix, self.salt, self.digest)
    }
}

fn itoa64_index(byte: u8) -> Option<u32> {
    ITOA64
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u32)
}
