//! XCA database passwords, rendered as a prefixed base64 blob.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// XCA database password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "XCA database", slug = "xca", hashcat = [40000])]
pub struct Xca {
    /// Encoded payload
    #[field(role = salt, encoding = ascii)]
    pub payload: String,
}

impl Parse for Xca {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "T", 0)?;
        if rest.len() < 16 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "XCA payloads are at least 17 characters",
            ));
        }
        Ok(Self {
            payload: rest.to_owned(),
        })
    }
}

impl Render for Xca {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("T{}", self.payload)
    }
}
