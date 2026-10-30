//! SHA1 of MD5, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SHA1 of MD5.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA1 of MD5",
    slug = "sha1-md5",
    hashcat = [21100],
)]
pub struct Sha1Md5 {
    /// The 20-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for Sha1Md5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let Some(separator) = input.find(':') else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                input.len(),
                "expected `:` between digest and salt",
            ));
        };

        let salt = &input[separator + 1..];
        if let Some(offset) = salt.find(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                separator + 1 + offset,
                "salt must not contain `:`",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<20>(&input[..separator], 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for Sha1Md5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
