//! MurmurHash64A, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// MurmurHash64A values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MurmurHash64A",
    slug = "murmurhash64a",
    hashcat = [34200],
)]
pub struct MurmurHash64A {
    /// 8-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],

    /// 8-byte salt or seed
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],
}

impl Parse for MurmurHash64A {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<8>(digest, 0, "digest")?,
            salt: parse::decode_hex_field::<8>(salt, salt_offset, "salt")?,
        })
    }
}

impl Render for MurmurHash64A {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(self.salt)
        )
    }
}
