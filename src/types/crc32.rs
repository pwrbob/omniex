//! CRC32, rendered as `<digest>:<initial>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// CRC32 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "CRC32",
    slug = "crc32",
    hashcat = [11500],
    john = ["CRC32"],
)]
pub struct Crc32 {
    /// 4-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 4],

    /// 4-byte initial value
    #[field(role = other, encoding = hex)]
    pub initial: [u8; 4],
}

impl Parse for Crc32 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if let Some(rest) = input.strip_prefix("$crc32$") {
            let (initial, digest, digest_offset) = parse::split_once(rest, '.', 7)?;
            return Ok(Self {
                digest: parse::decode_hex_field::<4>(digest, digest_offset, "digest")?,
                initial: parse::decode_hex_field::<4>(initial, 7, "initial")?,
            });
        }
        let (digest, initial, initial_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<4>(digest, 0, "digest")?,
            initial: parse::decode_hex_field::<4>(initial, initial_offset, "initial")?,
        })
    }
}

impl Render for Crc32 {
    fn render_value(&self, opts: &RenderOptions) -> String {
        if opts.tool == crate::Tool::John {
            format!(
                "$crc32${}.{}",
                crate::format::hex(self.initial),
                crate::format::hex(self.digest)
            )
        } else {
            format!(
                "{}:{}",
                crate::format::hex(self.digest),
                crate::format::hex(self.initial)
            )
        }
    }
}
