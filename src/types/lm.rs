//! LM, rendered as a bare 16-digit hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single LM digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "LM",
    slug = "lm",
    hashcat = [3000],
)]
pub struct Lm {
    /// The 8-byte LM digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for Lm {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<8>(input, 0, "digest")?,
        })
    }
}

impl Render for Lm {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
