//! MD5 with salt on both sides, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MD5 with salt on both sides.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MD5 with salt on both sides",
    slug = "md5-sandwich-salt",
    hashcat = [40071],
)]
pub struct Md5SandwichSalt {
    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for Md5SandwichSalt {
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
            digest: parse::decode_hex_field::<16>(&input[..separator], 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for Md5SandwichSalt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
