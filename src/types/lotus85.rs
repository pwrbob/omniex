//! Lotus Notes 8.5 hashes, rendered as a bare hexadecimal blob.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Lotus Notes 8.5 password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Lotus Notes 8.5", slug = "lotus85", hashcat = [], john = ["lotus85"])]
pub struct Lotus85 {
    /// User blob (16-100 bytes)
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

impl Parse for Lotus85 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let data = parse::decode_hex(input, 0)?;
        if !(16..=100).contains(&data.len()) {
            return Err(parse::error(
                crate::ParseErrorKind::InvalidLength,
                0,
                "Lotus Notes 8.5 blob must be 16 to 100 bytes",
            ));
        }
        Ok(Self { data })
    }
}

impl Render for Lotus85 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.data).to_uppercase()
    }
}
