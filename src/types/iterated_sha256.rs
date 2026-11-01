//! Iterated-SHA256 hashes, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Iterated-SHA256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Iterated-SHA256", slug = "iterated-sha256", hashcat = [], john = ["Iterated-SHA256"])]
pub struct IteratedSha256 {
    /// The 64-byte SHA-256 iteration state.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for IteratedSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<64>(input, 0, "digest")?,
        })
    }
}

impl Render for IteratedSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
