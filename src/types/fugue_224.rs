//! Fugue-224, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single Fugue-224 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Fugue-224",
    slug = "fugue-224",
    hashcat = [40133],
)]
pub struct Fugue224 {
    /// The 28-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 28],
}

impl Parse for Fugue224 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<28>(input, 0, "digest")?,
        })
    }
}

impl Render for Fugue224 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
