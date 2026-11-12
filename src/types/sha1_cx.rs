//! sha1(CX), rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// sha1(CX) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "sha1(CX)",
    slug = "sha1-cx",
    hashcat = [14400],
)]
pub struct Sha1Cx {
    /// 20-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// 10-byte salt or seed
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 10],
}

impl Parse for Sha1Cx {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<20>(digest, 0, "digest")?,
            salt: parse::decode_hex_field::<10>(salt, salt_offset, "salt")?,
        })
    }
}

impl Render for Sha1Cx {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(self.salt)
        )
    }
}
