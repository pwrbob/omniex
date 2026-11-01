//! Lotus Notes 8.5 hashes, rendered as a bare hexadecimal blob.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Lotus Notes 8.5 password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Lotus Notes 8.5", slug = "lotus85", hashcat = [], john = ["lotus85"])]
pub struct Lotus85 {
    /// The 56-byte user blob.
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 56],
}

impl Parse for Lotus85 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            data: parse::decode_hex_field::<56>(input, 0, "data")?,
        })
    }
}

impl Render for Lotus85 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.data).to_uppercase()
    }
}
