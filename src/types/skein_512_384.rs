//! Skein-512-384, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single Skein-512-384 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Skein-512-384",
    slug = "skein-512-384",
    hashcat = [40098],
)]
pub struct Skein512_384 {
    /// The 48-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 48],
}

impl Parse for Skein512_384 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<48>(input, 0, "digest")?,
        })
    }
}

impl Render for Skein512_384 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
