//! Skip32 (PT = $salt, key = $pass), rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Skip32 (PT = $salt, key = $pass) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Skip32 (PT = $salt, key = $pass)",
    slug = "skip32",
    hashcat = [14900],
)]
pub struct Skip32 {
    /// The 4-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 4],

    /// The 4-byte salt or seed.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 4],
}

impl Parse for Skip32 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<4>(digest, 0, "digest")?,
            salt: parse::decode_hex_field::<4>(salt, salt_offset, "salt")?,
        })
    }
}

impl Render for Skip32 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(self.salt)
        )
    }
}
