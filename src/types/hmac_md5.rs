//! HMAC-MD5, rendered as `<digest>:<key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// HMAC-MD5 with the password or the salt as the key.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "HMAC-MD5",
    slug = "hmac-md5",
    hashcat = [50, 60],
    modes_fn = hmac_md5_modes,
)]
pub struct HmacMd5 {
    /// The 16-byte HMAC-MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// HMAC key, serialized as ASCII.
    #[field(role = key, encoding = ascii)]
    pub key: String,
}

impl Parse for HmacMd5 {
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
            digest: parse::decode_hex_field::<16>(&input[..separator], 0, "digest")?,
            key: key.to_owned(),
        })
    }
}

pub fn hmac_md5_modes(value: &HmacMd5) -> Vec<crate::Mode> {
    if value.key.chars().count() > 256 {
        return Vec::new();
    }

    HmacMd5::DESCRIPTOR.all_modes.to_vec()
}

impl Render for HmacMd5 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.key)
    }
}
