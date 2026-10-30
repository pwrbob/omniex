//! Whirlpool-T, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single Whirlpool-T digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Whirlpool-T",
    slug = "whirlpool-t",
    hashcat = [40175],
)]
pub struct WhirlpoolT {
    /// The 64-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for WhirlpoolT {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<64>(input, 0, "digest")?,
        })
    }
}

impl Render for WhirlpoolT {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
