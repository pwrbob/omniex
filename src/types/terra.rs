//! Terra Station wallet, rendered as `<salt><iv><ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Terra Station wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Terra Station Wallet",
    slug = "terra",
    hashcat = [29600],
)]
pub struct Terra {
    /// 16-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// 16-byte IV
    #[field(role = iv, encoding = hex)]
    pub iv: [u8; 16],

    /// Base64 ciphertext
    #[field(role = ciphertext, encoding = ascii)]
    pub ciphertext: String,
}

impl Parse for Terra {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let Some(salt) = input.get(..32) else {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Terra values contain a salt and IV",
            ));
        };
        let Some(iv) = input.get(32..64) else {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Terra values contain a salt and IV",
            ));
        };
        let ciphertext = input.get(64..).unwrap_or_default();
        Ok(Self {
            salt: parse::decode_hex_field::<16>(salt, 0, "salt")?,
            iv: parse::decode_hex_field::<16>(iv, 32, "iv")?,
            ciphertext: ciphertext.to_owned(),
        })
    }
}

impl Render for Terra {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.iv),
            self.ciphertext
        )
    }
}
