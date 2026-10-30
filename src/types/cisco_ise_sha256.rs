//! Cisco-ISE hashed password, rendered as `<digest><salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Cisco-ISE SHA2-256 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Cisco-ISE Hashed Password (SHA256)",
    slug = "cisco-ise-sha256",
    hashcat = [40012],
)]
pub struct CiscoIseSha256 {
    /// The 32-byte SHA2-256 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// The 32-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],
}

impl Parse for CiscoIseSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 128 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Cisco-ISE values are 128 hexadecimal digits",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<32>(&input[..64], 0, "digest")?,
            salt: parse::decode_hex_field::<32>(&input[64..], 64, "salt")?,
        })
    }
}

impl Render for CiscoIseSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}",
            crate::format::hex(self.digest),
            crate::format::hex(self.salt)
        )
    }
}
