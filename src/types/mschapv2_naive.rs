//! mschapv2-naive hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// mschapv2-naive hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "mschapv2-naive", slug = "mschapv2-naive", hashcat = [], john = ["mschapv2-naive"])]
pub struct Mschapv2NaiveJohn {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Mschapv2NaiveJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 6)?;
        parse::check_hex_length(fields[3].0, fields[3].1, 32, "peer challenge")?;
        parse::check_hex_length(fields[4].0, fields[4].1, 48, "response")?;
        parse::check_hex_length(fields[5].0, fields[5].1, 32, "challenge")?;
        Ok(Self {
            data: input.to_owned(),
        })
    }
}

impl Render for Mschapv2NaiveJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.data.clone()
    }
}
