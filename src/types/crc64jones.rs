//! CRC64Jones, rendered as `<digest>:<initial>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// CRC64Jones hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "CRC64Jones",
    slug = "crc64jones",
    hashcat = [28000],
)]
pub struct Crc64Jones {
    /// 8-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],

    /// 8-byte initial value
    #[field(role = other, encoding = hex)]
    pub initial: [u8; 8],
}

impl Parse for Crc64Jones {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, initial, initial_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<8>(digest, 0, "digest")?,
            initial: parse::decode_hex_field::<8>(initial, initial_offset, "initial")?,
        })
    }
}

impl Render for Crc64Jones {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(self.initial)
        )
    }
}
