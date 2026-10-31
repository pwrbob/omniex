//! ShangMi 3, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single SM3 digest.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "ShangMi 3 (SM3)", slug = "sm3", hashcat = [31100])]
pub struct Sm3 {
    /// Thirty-two-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Sm3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<32>(input, 0, "digest")?,
        })
    }
}

impl Render for Sm3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
