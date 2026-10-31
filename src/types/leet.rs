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
        let (salt, digest, digest_offset) = parse::split_once(input, '$', 0)?;
        if digest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "missing leet digest",
            ));
        }
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
