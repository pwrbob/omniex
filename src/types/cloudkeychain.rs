//! cloudkeychain hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// cloudkeychain hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "cloudkeychain", slug = "cloudkeychain", hashcat = [], john = ["cloudkeychain"])]
pub struct CloudkeychainJohn {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for CloudkeychainJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$cloudkeychain$", 0)?;
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

impl Render for CloudkeychainJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$cloudkeychain${}", self.data)
    }
}
