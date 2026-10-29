//! HMAC-SHA512, rendered as `<digest>:<key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// HMAC-SHA512 with the password or the salt as the key.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "HMAC-SHA512",
    slug = "hmac-sha512",
    hashcat = [1750, 1760],
    modes_fn = hmac_sha512_modes,
)]
pub struct HmacSha512 {
    /// The 64-byte HMAC-SHA512 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],

    /// HMAC key, serialized as ASCII.
    #[field(role = key, encoding = ascii)]
    pub key: String,
}

pub fn hmac_sha512_modes(value: &HmacSha512) -> Vec<crate::Mode> {
    if value.key.chars().count() > 256 {
        return Vec::new();
    }

    HmacSha512::DESCRIPTOR.all_modes.to_vec()
}

impl Parse for HmacSha512 {
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
            digest: parse::decode_hex_field::<64>(&input[..separator], 0, "digest")?,
            key: key.to_owned(),
        })
    }
}

impl Render for HmacSha512 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.key)
    }
}
