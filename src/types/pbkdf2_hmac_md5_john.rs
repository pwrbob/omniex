//! PBKDF2-HMAC-MD5 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PBKDF2-HMAC-MD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PBKDF2-HMAC-MD5 legacy", slug = "pbkdf2-hmac-md5-legacy", hashcat = [], john = ["PBKDF2-HMAC-MD5"])]
pub struct Pbkdf2HmacMd5John {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Pbkdf2HmacMd5John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pbkdf2-hmac-md5$", 0)?;
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

impl Render for Pbkdf2HmacMd5John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$pbkdf2-hmac-md5${}", self.data)
    }
}
