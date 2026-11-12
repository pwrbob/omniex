//! AES-256-ECB NOKDF (PT = $salt, key = $pass), rendered as `<ciphertext>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// AES-256-ECB NOKDF (PT = $salt, key = $pass) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "AES-256-ECB NOKDF (PT = $salt, key = $pass)",
    slug = "aes256-ecb-nokdf",
    hashcat = [26403],
)]
pub struct Aes256EcbNokdf {
    /// 16-byte ciphertext
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: [u8; 16],

    /// 16-byte salt or plaintext
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],
}

impl Parse for Aes256EcbNokdf {
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

impl Render for Aes256EcbNokdf {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.ciphertext),
            crate::format::hex(self.salt)
        )
    }
}
