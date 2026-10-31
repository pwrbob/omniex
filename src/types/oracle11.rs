//! Oracle 11 hashes, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Oracle 11g hashes in the John serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Oracle 11", slug = "oracle11", hashcat = [], john = ["oracle11"])]
pub struct Oracle11 {
    /// Thirty-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 30],
}

impl Parse for Oracle11 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<30>(input, 0, "digest")?,
        })
    }
}

impl Render for Oracle11 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest).to_uppercase()
    }
}
