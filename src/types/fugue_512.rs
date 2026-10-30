//! Fugue-512, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single Fugue-512 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Fugue-512",
    slug = "fugue-512",
    hashcat = [40136],
)]
pub struct Fugue512 {
    /// The 64-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for Fugue512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<64>(input, 0, "digest")?,
        })
    }
}

impl Render for Fugue512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
