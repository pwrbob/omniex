//! HMAC-SHA1, rendered as `<digest>:<key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// HMAC-SHA1 with the password or the salt as the key.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "HMAC-SHA1",
    slug = "hmac-sha1",
    hashcat = [150, 160],
    modes_fn = hmac_sha1_modes,
)]
pub struct HmacSha1 {
    /// The 20-byte HMAC-SHA1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// HMAC key, serialized as ASCII.
    #[field(role = key, encoding = ascii)]
    pub key: String,
}

impl Parse for HmacSha1 {
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
            digest: parse::decode_hex_field::<20>(&input[..separator], 0, "digest")?,
            key: key.to_owned(),
        })
    }
}

pub fn hmac_sha1_modes(value: &HmacSha1) -> Vec<crate::Mode> {
    if value.key.chars().count() > 256 {
        return Vec::new();
    }

    HmacSha1::DESCRIPTOR.all_modes.to_vec()
}

impl Render for HmacSha1 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.key)
    }
}
