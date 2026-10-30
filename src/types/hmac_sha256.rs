//! HMAC-SHA256, rendered as `<digest>:<key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// HMAC-SHA256 with the password or the salt as the key.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "HMAC-SHA256",
    slug = "hmac-sha256",
    hashcat = [1450, 1460],
    modes_fn = hmac_sha256_modes,
)]
pub struct HmacSha256 {
    /// The 32-byte HMAC-SHA256 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// HMAC key, serialized as ASCII.
    #[field(role = key, encoding = ascii)]
    pub key: String,
}

pub fn hmac_sha256_modes(value: &HmacSha256) -> Vec<crate::Mode> {
    if value.key.len() > 256 {
        return Vec::new();
    }

    HmacSha256::DESCRIPTOR.all_modes.to_vec()
}

impl Parse for HmacSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let Some(separator) = input.find(':') else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                input.len(),
                "expected `:` between digest and key",
            ));
        };

        let key = &input[separator + 1..];
        if let Some(offset) = key.find(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                separator + 1 + offset,
                "key must not contain `:`",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<32>(&input[..separator], 0, "digest")?,
            key: key.to_owned(),
        })
    }
}

impl Render for HmacSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.key)
    }
}
