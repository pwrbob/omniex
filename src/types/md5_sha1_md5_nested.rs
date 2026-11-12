//! Nested MD5 inside SHA1 inside MD5, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A digest of `md5(sha1(md5($pass)))`.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "md5(sha1(md5($pass)))",
    slug = "md5-sha1-md5-nested",
    hashcat = [32800]
)]
pub struct Md5Sha1Md5Nested {
    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Md5Sha1Md5Nested {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<16>(input, 0, "digest")?,
        })
    }
}

impl Render for Md5Sha1Md5Nested {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
