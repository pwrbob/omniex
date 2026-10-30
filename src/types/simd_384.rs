//! SIMD-384, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single SIMD-384 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "SIMD-384",
    slug = "simd-384",
    hashcat = [40163],
)]
pub struct Simd384 {
    /// The 48-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 48],
}

impl Parse for Simd384 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<48>(input, 0, "digest")?,
        })
    }
}

impl Render for Simd384 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
