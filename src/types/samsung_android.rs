//! Samsung Android password/PIN, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Samsung Android password/PIN hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Samsung Android",
    slug = "samsung-android",
    hashcat = [5800],
)]
pub struct SamsungAndroid {
    /// 20-byte SHA-1 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Decimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for SamsungAndroid {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        if salt.is_empty() || !salt.bytes().all(|b| b.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "Samsung salt must be decimal digits",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<20>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for SamsungAndroid {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
