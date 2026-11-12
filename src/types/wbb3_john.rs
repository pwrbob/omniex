//! wbb3 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// wbb3 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "WBB3 payload", slug = "wbb3-payload", hashcat = [], john = ["wbb3"])]
pub struct Wbb3John {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Wbb3John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$wbb3$", 0)?;
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

impl Render for Wbb3John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$wbb3${}", self.data)
    }
}
