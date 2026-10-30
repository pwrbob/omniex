//! Tiger2, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single Tiger2 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Tiger2",
    slug = "tiger2",
    hashcat = [40092],
)]
pub struct Tiger2 {
    /// The 24-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 24],
}

impl Parse for Tiger2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<24>(input, 0, "digest")?,
        })
    }
}

impl Render for Tiger2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
