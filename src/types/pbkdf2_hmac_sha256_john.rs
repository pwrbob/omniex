//! PBKDF2-HMAC-SHA256 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PBKDF2-HMAC-SHA256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PBKDF2-HMAC-SHA256 legacy", slug = "pbkdf2-hmac-sha256-legacy", hashcat = [], john = ["PBKDF2-HMAC-SHA256"])]
pub struct Pbkdf2HmacSha256John {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Pbkdf2HmacSha256John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = match input.strip_prefix("$pbkdf2-hmac-sha256$") {
            Some(rest) => rest,
            None => parse::strip_prefix(input, "$pbkdf2-sha256$", 0)?,
        };
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

impl Render for Pbkdf2HmacSha256John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$pbkdf2-sha256${}", self.data)
    }
}
