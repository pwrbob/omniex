//! SHA2-512 of binary SHA2-512 and salt, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SHA2-512 of binary SHA2-512 and salt.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA2-512 of binary SHA2-512 and salt",
    slug = "sha512-double-bin-salt",
    hashcat = [40068],
)]
pub struct Sha512DoubleBinSalt {
    /// The 64-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for Sha512DoubleBinSalt {
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
            digest: parse::decode_hex_field::<64>(&input[..separator], 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for Sha512DoubleBinSalt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
