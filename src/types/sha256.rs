//! SHA2-256, rendered as a bare 64-digit hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single SHA2-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA2-256",
    slug = "sha256",
    hashcat = [1400, 1470],
    john = ["Raw-SHA256"],
)]
pub struct Sha256 {
    /// The 32-byte SHA2-256 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Sha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<32>(input, 0, "digest")?,
        })
    }
}

impl Render for Sha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
