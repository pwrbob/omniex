//! CubeCart salted Whirlpool, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// CubeCart salted Whirlpool.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "CubeCart salted Whirlpool",
    slug = "whirlpool-cubecart",
    hashcat = [40069],
)]
pub struct WhirlpoolCubeCart {
    /// 64-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for WhirlpoolCubeCart {
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

impl Render for WhirlpoolCubeCart {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
