//! Half MD5, rendered as a bare 16-digit hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// The first half of an MD5 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Half MD5",
    slug = "half-md5",
    hashcat = [5100],
)]
pub struct HalfMd5 {
    /// 8-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for HalfMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<8>(input, 0, "digest")?,
        })
    }
}

impl Render for HalfMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
