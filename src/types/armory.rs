//! Armory wallet hashes, rendered as a base64 payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Armory wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Armory", slug = "armory", hashcat = [], john = ["armory"])]
pub struct Armory {
    /// Base64-encoded wallet payload.
    #[field(role = other, encoding = base64)]
    pub data: Vec<u8>,
}

impl Parse for Armory {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            data: parse::decode_base64(input, 0)?,
        })
    }
}

impl Render for Armory {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::base64(&self.data)
    }
}
