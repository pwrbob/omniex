//! Juniper NetScreen/SSG (ScreenOS), rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Juniper NetScreen/SSG (ScreenOS) password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Juniper ScreenOS",
    slug = "juniper-screenos",
    hashcat = [22],
)]
pub struct JuniperScreenos {
    /// The 30-character ScreenOS digest encoding.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,

    /// Decimal salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for JuniperScreenos {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;

        if digest.len() != 30 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "ScreenOS digest must be 30 characters",
            ));
        }
        if salt.is_empty() || !salt.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "ScreenOS salt must be decimal digits",
            ));
        }

        Ok(Self {
            digest: digest.to_owned(),
            salt: salt.to_owned(),
        })
    }
}

impl Render for JuniperScreenos {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", self.digest, self.salt)
    }
}
