//! Leet hashes, rendered as `<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Leet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "leet", slug = "leet", hashcat = [], john = ["leet"])]
pub struct Leet {
    /// Salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Hexadecimal digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Leet {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let Some(index) = input.rfind('$') else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                input.len(),
                "expected `$` between the salt and the digest",
            ));
        };
        let salt = &input[..index];
        let digest = &input[index + 1..];
        if salt.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "missing leet salt",
            ));
        }
        parse::check_text_length(salt, 0, 32, "leet salt")?;
        if digest.len() != 128 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                index + 1,
                "leet digests are 128 hexadecimal digits",
            ));
        }
        parse::check_hex(digest, index + 1, "leet digest")?;
        Ok(Self {
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Leet {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}${}", self.salt, self.digest)
    }
}
