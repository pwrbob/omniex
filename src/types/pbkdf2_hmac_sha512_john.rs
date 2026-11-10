//! PBKDF2-HMAC-SHA512 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PBKDF2-HMAC-SHA512 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PBKDF2-HMAC-SHA512 legacy", slug = "pbkdf2-hmac-sha512-legacy", hashcat = [], john = ["PBKDF2-HMAC-SHA512"])]
pub struct Pbkdf2HmacSha512John {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Pbkdf2HmacSha512John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pbkdf2-hmac-sha512$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "missing hash payload",
            ));
        }
        Ok(Self {
            data: rest.to_owned(),
        })
    }
}

impl Render for Pbkdf2HmacSha512John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$pbkdf2-hmac-sha512${}", self.data)
    }
}
