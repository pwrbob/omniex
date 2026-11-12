//! netlm hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// netlm hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "netlm", slug = "netlm", hashcat = [], john = ["netlm"])]
pub struct NetlmJohn {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for NetlmJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 6)?;
        if fields[4].0.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[4].1,
                "LM challenges need an NT response alongside the LM response",
            ));
        }
        parse::check_hex_length(fields[3].0, fields[3].1, 48, "LM response")?;
        parse::check_hex_length(fields[5].0, fields[5].1, 16, "challenge")?;
        Ok(Self {
            data: input.to_owned(),
        })
    }
}

impl Render for NetlmJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.data.clone()
    }
}
