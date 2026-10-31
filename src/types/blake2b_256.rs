//! BLAKE2b-256, rendered as `$BLAKE2$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single BLAKE2b-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "BLAKE2b-256", slug = "blake2b-256", hashcat = [34800])]
pub struct Blake2b256 {
    /// Thirty-two-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Blake2b256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$BLAKE2$", 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<32>(rest, 8, "digest")?,
        })
    }
}

impl Render for Blake2b256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$BLAKE2${}", crate::format::hex(self.digest))
    }
}
