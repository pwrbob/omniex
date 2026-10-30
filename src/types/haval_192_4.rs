//! HAVAL-192 (4 passes), rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single HAVAL-192 (4 passes) digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "HAVAL-192 (4 passes)",
    slug = "haval-192-4",
    hashcat = [40109],
)]
pub struct Haval192_4 {
    /// The 24-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 24],
}

impl Parse for Haval192_4 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<24>(input, 0, "digest")?,
        })
    }
}

impl Render for Haval192_4 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
