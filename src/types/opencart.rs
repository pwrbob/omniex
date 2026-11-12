//! OpenCart, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// OpenCart values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "OpenCart",
    slug = "opencart",
    hashcat = [13900],
)]
pub struct Opencart {
    /// 20-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for Opencart {
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
            digest: parse::decode_hex_field::<20>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for Opencart {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
