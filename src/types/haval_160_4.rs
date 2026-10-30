//! HAVAL-160 (4 passes), rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single HAVAL-160 (4 passes) digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "HAVAL-160 (4 passes)",
    slug = "haval-160-4",
    hashcat = [40106],
)]
pub struct Haval160_4 {
    /// The 20-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for Haval160_4 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<20>(input, 0, "digest")?,
        })
    }
}

impl Render for Haval160_4 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
