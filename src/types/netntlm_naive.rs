//! netntlm-naive hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// netntlm-naive hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "netntlm-naive", slug = "netntlm-naive", hashcat = [], john = ["netntlm-naive"])]
pub struct NetntlmNaiveJohn {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for NetntlmNaiveJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 6)?;
        if fields[3].0.is_empty() || fields[5].0.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "missing challenge-response field",
            ));
        }
        Ok(Self {
            data: input.to_owned(),
        })
    }
}

impl Render for NetntlmNaiveJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.data.clone()
    }
}
