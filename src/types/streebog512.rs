//! GOST R 34.11-2012 (Streebog) 512-bit, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single GOST R 34.11-2012 (Streebog) 512-bit digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "GOST R 34.11-2012 (Streebog) 512-bit",
    slug = "streebog-512",
    hashcat = [11800],
)]
pub struct Streebog512 {
    /// 64-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for Streebog512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<64>(input, 0, "digest")?,
        })
    }
}

impl Render for Streebog512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
