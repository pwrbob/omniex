//! SHA2-512, rendered as a bare 128-digit hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single SHA2-512 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA2-512",
    slug = "sha512",
    hashcat = [1700, 1770],
    john = ["Raw-SHA512"],
)]
pub struct Sha512 {
    /// 64-byte SHA2-512 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for Sha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<64>(input, 0, "digest")?,
        })
    }
}

impl Render for Sha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
