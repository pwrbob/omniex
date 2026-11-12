//! SHA2-256 of salt and binary SHA2-256, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SHA2-256 of salt and binary SHA2-256.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA2-256 of salt and binary SHA2-256",
    slug = "sha256-salt-sha256-bin",
    hashcat = [40049],
)]
pub struct Sha256SaltSha256Bin {
    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for Sha256SaltSha256Bin {
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
            digest: parse::decode_hex_field::<32>(&input[..separator], 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for Sha256SaltSha256Bin {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
