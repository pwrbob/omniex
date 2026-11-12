//! Bitwarden hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Bitwarden hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Bitwarden payload", slug = "bitwarden-payload", hashcat = [], john = ["Bitwarden"])]
pub struct BitwardenJohn {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for BitwardenJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$bitwarden$", 0)?;
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

impl Render for BitwardenJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$bitwarden${}", self.data)
    }
}
