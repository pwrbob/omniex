//! AES-192-ECB NOKDF (PT = $salt, key = $pass), rendered as `<ciphertext>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// AES-192-ECB NOKDF (PT = $salt, key = $pass) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "AES-192-ECB NOKDF (PT = $salt, key = $pass)",
    slug = "aes192-ecb-nokdf",
    hashcat = [26402],
)]
pub struct Aes192EcbNokdf {
    /// The 16-byte ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: [u8; 16],

    /// The 16-byte salt or plaintext.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],
}

impl Parse for Aes192EcbNokdf {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (ciphertext, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            ciphertext: parse::decode_hex_field::<16>(ciphertext, 0, "ciphertext")?,
            salt: parse::decode_hex_field::<16>(salt, salt_offset, "salt")?,
        })
    }
}

impl Render for Aes192EcbNokdf {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.ciphertext),
            crate::format::hex(self.salt)
        )
    }
}
