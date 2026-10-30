//! ColdFusion 10+, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// ColdFusion 10+ values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "ColdFusion 10+",
    slug = "coldfusion10",
    hashcat = [12600],
)]
pub struct ColdFusion10 {
    /// The 32-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for ColdFusion10 {
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

impl Render for ColdFusion10 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
