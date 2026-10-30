//! Symfony Legacy SHA256, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Symfony Legacy SHA256 values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Symfony Legacy SHA256",
    slug = "symfony-legacy-sha256",
    hashcat = [35800],
)]
pub struct SymfonyLegacySha256 {
    /// The 32-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for SymfonyLegacySha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        if salt.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "salt must not contain `:`",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<32>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for SymfonyLegacySha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
