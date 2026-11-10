//! Mozilla hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Mozilla hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Mozilla payload", slug = "mozilla-payload", hashcat = [], john = ["Mozilla"])]
pub struct MozillaJohn {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for MozillaJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mozilla$", 0)?;
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

impl Render for MozillaJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$mozilla${}", self.data)
    }
}
