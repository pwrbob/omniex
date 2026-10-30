//! SHA2-256 of MD5, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single SHA2-256 of MD5 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA2-256 of MD5",
    slug = "sha256-md5",
    hashcat = [20800],
)]
pub struct Sha256Md5 {
    /// The 32-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Sha256Md5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<32>(input, 0, "digest")?,
        })
    }
}

impl Render for Sha256Md5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
