//! RIPEMD-160, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single RIPEMD-160 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "RIPEMD-160",
    slug = "ripemd-160",
    hashcat = [6000],
)]
pub struct Ripemd160 {
    /// The 20-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for Ripemd160 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<20>(input, 0, "digest")?,
        })
    }
}

impl Render for Ripemd160 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
