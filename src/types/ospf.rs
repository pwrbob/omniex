//! ospf hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// ospf hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "ospf", slug = "ospf", hashcat = [], john = ["ospf"])]
pub struct OspfJohn {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for OspfJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$ospf$", 0)?;
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

impl Render for OspfJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$ospf${}", self.data)
    }
}
