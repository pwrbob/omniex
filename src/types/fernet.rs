//! Fernet tokens, rendered as their base64 ciphertext.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Fernet key-derived tokens.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Fernet (key = SHA256($pass))",
    slug = "fernet",
    hashcat = [40083],
)]
pub struct Fernet {
    /// Base64-encoded Fernet token.
    #[field(role = ciphertext, encoding = ascii)]
    pub token: String,
}

impl Parse for Fernet {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if !(98..=376).contains(&input.len())
            || !input
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
        {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Fernet tokens are 98 to 376 URL-safe base64 characters",
            ));
        }
        Ok(Self {
            token: input.to_owned(),
        })
    }
}

impl Render for Fernet {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.token.clone()
    }
}
