//! Password Safe v3 database headers, rendered as the raw 360-byte header in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Password Safe v3 database header.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Password Safe v3",
    slug = "pwsafe-v3",
    hashcat = [40011],
)]
pub struct PwsafeV3 {
    /// Four-byte `PWS3` signature.
    #[field(role = other, encoding = ascii)]
    pub signature: String,

    /// Thirty-two-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],

    /// PBKDF2-SHA256 iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Thirty-two-byte verification hash.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Remaining database header bytes.
    #[field(role = ciphertext, encoding = hex)]
    pub payload: Vec<u8>,
}

impl Parse for PwsafeV3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 720 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Password Safe v3 header must be 720 hexadecimal digits",
            ));
        }
        let signature = parse::decode_hex_field::<4>(&input[..8], 0, "signature")?;
        if &signature != b"PWS3" {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected `PWS3` signature",
            ));
        }
        let iteration_bytes = parse::decode_hex_field::<4>(&input[72..80], 72, "iterations")?;
        Ok(Self {
            signature: String::from_utf8(signature.to_vec()).expect("PWS3 is ASCII"),
            salt: parse::decode_hex_field::<32>(&input[8..72], 8, "salt")?,
            iterations: u32::from_le_bytes(iteration_bytes),
            digest: parse::decode_hex_field::<32>(&input[80..144], 80, "digest")?,
            payload: parse::decode_hex(&input[144..], 144)?,
        })
    }
}

impl Render for PwsafeV3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}{}{}{}",
            crate::format::hex(self.signature.as_bytes()),
            crate::format::hex(self.salt),
            crate::format::hex(self.iterations.to_le_bytes()),
            crate::format::hex(self.digest),
            crate::format::hex(&self.payload)
        )
    }
}
