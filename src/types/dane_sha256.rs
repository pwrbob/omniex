//! DANE TLSA SHA2-256 hashes, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// DANE RFC7929/RFC8162 SHA2-256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "DANE RFC7929/RFC8162 SHA2-256",
    slug = "dane-sha256",
    hashcat = [30420]
)]
pub struct DaneSha256 {
    /// 28-byte SHA-224 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 28],
}

impl Parse for DaneSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<28>(input, 0, "digest")?,
        })
    }
}

impl Render for DaneSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
