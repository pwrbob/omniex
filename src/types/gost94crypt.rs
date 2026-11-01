//! gost94crypt hashes, rendered as `$gost94hash$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// gost94crypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "gost94crypt", slug = "gost94crypt", hashcat = [], john = ["gost94crypt"])]
pub struct Gost94crypt {
    /// ASCII salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Crypt base64 digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Gost94crypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$gost94hash$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 13)?;
        if salt.is_empty() || digest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "gost94crypt salt and digest must not be empty",
            ));
        }
        Ok(Self {
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Gost94crypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$gost94hash${}${}", self.salt, self.digest)
    }
}
