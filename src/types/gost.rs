//! GOST R 34.11-94, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single GOST R 34.11-94 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "GOST R 34.11-94",
    slug = "gost",
    hashcat = [6900],
)]
pub struct Gost {
    /// The 32-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Gost {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<32>(input, 0, "digest")?,
        })
    }
}

impl Render for Gost {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
