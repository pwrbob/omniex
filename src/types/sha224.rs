//! SHA2-224, rendered as a bare 56-digit hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single SHA2-224 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA2-224",
    slug = "sha224",
    hashcat = [1300],
    john = ["Raw-SHA224"],
)]
pub struct Sha224 {
    /// 28-byte SHA2-224 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 28],
}

impl Parse for Sha224 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<28>(input, 0, "digest")?,
        })
    }
}

impl Render for Sha224 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
