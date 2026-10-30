//! 3DES (PT = $salt, key = $pass), rendered as `<ciphertext>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// 3DES (PT = $salt, key = $pass) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "3DES (PT = $salt, key = $pass)",
    slug = "des3-plaintext",
    hashcat = [14100],
)]
pub struct Des3Plaintext {
    /// The 8-byte ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: [u8; 8],

    /// The 8-byte salt or plaintext.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],
}

impl Parse for Des3Plaintext {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (ciphertext, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            ciphertext: parse::decode_hex_field::<8>(ciphertext, 0, "ciphertext")?,
            salt: parse::decode_hex_field::<8>(salt, salt_offset, "salt")?,
        })
    }
}

impl Render for Des3Plaintext {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.ciphertext),
            crate::format::hex(self.salt)
        )
    }
}
