//! HMAC-RIPEMD160 (key = $salt), rendered as `<digest>:<key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// HMAC-RIPEMD160 (key = $salt) values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "HMAC-RIPEMD160 (key = $salt)",
    slug = "hmac-ripemd160-salt",
    hashcat = [40014],
)]
pub struct HmacRipemd160Salt {
    /// The 20-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// HMAC key or salt, depending on the mode.
    #[field(role = key, encoding = ascii)]
    pub key: String,
}

impl Parse for HmacRipemd160Salt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, key, key_offset) = parse::split_once(input, ':', 0)?;
        if key.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                key_offset,
                "key must not contain `:`",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<20>(digest, 0, "digest")?,
            key: key.to_owned(),
        })
    }
}

impl Render for HmacRipemd160Salt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.key)
    }
}
