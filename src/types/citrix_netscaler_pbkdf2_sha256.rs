//! Citrix NetScaler PBKDF2-HMAC-SHA256, rendered as `5<salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Citrix NetScaler PBKDF2-HMAC-SHA256 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Citrix NetScaler (PBKDF2-HMAC-SHA256)",
    slug = "citrix-netscaler-pbkdf2-sha256",
    hashcat = [40075],
)]
pub struct CitrixNetScalerPbkdf2Sha256 {
    /// The 32-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],

    /// The 32-byte SHA2-256 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for CitrixNetScalerPbkdf2Sha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 129 || !input.starts_with('5') {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Citrix PBKDF2 values are 129 characters starting with `5`",
            ));
        }
        Ok(Self {
            salt: parse::decode_hex_field::<32>(&input[1..65], 1, "salt")?,
            digest: parse::decode_hex_field::<32>(&input[65..], 65, "digest")?,
        })
    }
}

impl Render for CitrixNetScalerPbkdf2Sha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "5{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
