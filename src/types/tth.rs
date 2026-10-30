//! TTH (Tiger Tree Hash, single leaf), rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single TTH (Tiger Tree Hash, single leaf) digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "TTH (Tiger Tree Hash, single leaf)",
    slug = "tth",
    hashcat = [40093],
)]
pub struct Tth {
    /// The 24-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 24],
}

impl Parse for Tth {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<24>(input, 0, "digest")?,
        })
    }
}

impl Render for Tth {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
