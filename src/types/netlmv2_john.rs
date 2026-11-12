//! netlmv2 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// netlmv2 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "NetLMv2 payload", slug = "netlmv2-payload", hashcat = [], john = ["netlmv2"])]
pub struct Netlmv2John {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Netlmv2John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 6)?;
        parse::check_hex_length(fields[3].0, fields[3].1, 16, "challenge")?;
        parse::check_hex_length(fields[4].0, fields[4].1, 32, "response")?;
        parse::check_hex_length(fields[5].0, fields[5].1, 16, "client challenge")?;
        Ok(Self {
            data: input.to_owned(),
        })
    }
}

impl Render for Netlmv2John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.data.clone()
    }
}
