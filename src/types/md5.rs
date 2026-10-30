//! MD5, rendered as a bare 32-digit hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single MD5 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MD5",
    slug = "md5",
    hashcat = [0, 70, 2600, 3500],
    john = ["Raw-MD5"],
)]
pub struct Md5 {
    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Md5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<16>(input, 0, "digest")?,
        })
    }
}

impl Render for Md5 {
    fn render(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
