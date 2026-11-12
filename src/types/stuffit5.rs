//! Stuffit5, rendered as a bare hexadecimal value.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Stuffit5 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Stuffit5",
    slug = "stuffit5",
    hashcat = [24700],
)]
pub struct Stuffit5 {
    /// 5-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 5],
}

impl Parse for Stuffit5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<5>(input, 0, "digest")?,
        })
    }
}

impl Render for Stuffit5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
