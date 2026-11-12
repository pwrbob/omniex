//! dominosec8 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// dominosec8 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "dominosec8", slug = "dominosec8", hashcat = [], john = ["dominosec8"])]
pub struct Dominosec8John {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Dominosec8John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "(", 0)?;
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

impl Render for Dominosec8John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("({}", self.data)
    }
}
