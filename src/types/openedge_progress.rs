//! OpenEdge Progress Encode, rendered as a sixteen-character value.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// OpenEdge Progress encoded values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "OpenEdge Progress Encode",
    slug = "openedge-progress",
    hashcat = [26200],
)]
pub struct OpenedgeProgress {
    /// 16-character encoded value
    #[field(role = digest, encoding = ascii)]
    pub value: String,
}

impl Parse for OpenedgeProgress {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 16 || !input.is_ascii() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "OpenEdge Progress values are sixteen ASCII characters",
            ));
        }
        Ok(Self {
            value: input.to_owned(),
        })
    }
}

impl Render for OpenedgeProgress {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.value.clone()
    }
}
