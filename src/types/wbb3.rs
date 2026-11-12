//! Woltlab Burning Board 3, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Woltlab Burning Board 3 SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "WBB3",
    slug = "wbb3",
    hashcat = [8400],
)]
pub struct Wbb3 {
    /// 20-byte SHA1 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Decimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for Wbb3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        if salt.is_empty() || !salt.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "WBB3 salt must be decimal",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<20>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for Wbb3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
