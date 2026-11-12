//! PBKDF2-HMAC-MD4 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PBKDF2-HMAC-MD4 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PBKDF2-HMAC-MD4", slug = "pbkdf2-hmac-md4", hashcat = [], john = ["PBKDF2-HMAC-MD4"])]
pub struct Pbkdf2HmacMd4John {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Pbkdf2HmacMd4John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pbkdf2-hmac-md4$", 0)?;
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

impl Render for Pbkdf2HmacMd4John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$pbkdf2-hmac-md4${}", self.data)
    }
}
