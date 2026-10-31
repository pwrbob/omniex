//! Lotus Notes/Domino 5, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Lotus Notes/Domino 5 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Lotus Notes/Domino 5",
    slug = "lotus5",
    hashcat = [8600],
)]
pub struct Lotus5 {
    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Lotus5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<16>(input, 0, "digest")?,
        })
    }
}

impl Render for Lotus5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
