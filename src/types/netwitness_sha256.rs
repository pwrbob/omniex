//! RSA NetWitness SHA2-256, rendered as `<DIGEST>:<salt>` with an uppercase digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// RSA Security Analytics / NetWitness SHA2-256.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetWitness SHA2-256",
    slug = "netwitness-sha256",
    hashcat = [20712],
)]
pub struct NetWitnessSha256 {
    /// 32-byte SHA2-256 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Base64 salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for NetWitnessSha256 {
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
        if salt.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                separator + 1,
                "salt must not contain `:`",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<32>(&input[..separator], 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for NetWitnessSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest).to_uppercase(),
            self.salt
        )
    }
}
