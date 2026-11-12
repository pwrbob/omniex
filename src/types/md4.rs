//! MD4, rendered as a bare 32-digit hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single MD4 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MD4",
    slug = "md4",
    hashcat = [900],
    john = ["Raw-MD4"],
)]
pub struct Md4 {
    /// 16-byte MD4 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Md4 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<16>(input, 0, "digest")?,
        })
    }
}

impl Render for Md4 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
