//! BLAKE2b-512, rendered as `$BLAKE2$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single BLAKE2b-512 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "BLAKE2b-512",
    slug = "blake2b-512",
    hashcat = [600],
    john = ["Raw-Blake2"],
)]
pub struct Blake2b512 {
    /// 64-byte BLAKE2b digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for Blake2b512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$BLAKE2$", 0)?;

        Ok(Self {
            digest: parse::decode_hex_field::<64>(rest, 8, "digest")?,
        })
    }
}

impl Render for Blake2b512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$BLAKE2${}", crate::format::hex(self.digest))
    }
}
