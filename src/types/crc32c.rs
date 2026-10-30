//! CRC32C, rendered as `<digest>:<initial>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// CRC32C hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "CRC32C",
    slug = "crc32c",
    hashcat = [27900],
)]
pub struct Crc32C {
    /// The 4-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 4],

    /// The 4-byte initial value.
    #[field(role = other, encoding = hex)]
    pub initial: [u8; 4],
}

impl Parse for Crc32C {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, initial, initial_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<4>(digest, 0, "digest")?,
            initial: parse::decode_hex_field::<4>(initial, initial_offset, "initial")?,
        })
    }
}

impl Render for Crc32C {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(self.initial)
        )
    }
}
