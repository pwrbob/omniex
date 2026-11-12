//! Password Safe v2 database headers, rendered as the raw 168-byte header in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Password Safe v2 database header.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Password Safe v2",
    slug = "pwsafe-v2",
    hashcat = [9000],
)]
pub struct PwsafeV2 {
    /// 8-byte Blowfish KDF salt
    #[field(role = salt, encoding = hex)]
    pub random: [u8; 8],

    /// 20-byte verification hash
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Reserved 20-byte salt field
    #[field(role = salt, encoding = hex)]
    pub reserved_salt: [u8; 20],

    /// Reserved eight-byte IV
    #[field(role = iv, encoding = hex)]
    pub reserved_iv: [u8; 8],

    /// Remaining DB header bytes
    #[field(role = ciphertext, encoding = hex)]
    pub payload: Vec<u8>,
}

impl Parse for PwsafeV2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 336 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Password Safe v2 header must be 336 hexadecimal digits",
            ));
        }
        Ok(Self {
            random: parse::decode_hex_field::<8>(&input[..16], 0, "random salt")?,
            digest: parse::decode_hex_field::<20>(&input[16..56], 16, "digest")?,
            reserved_salt: parse::decode_hex_field::<20>(&input[56..96], 56, "reserved salt")?,
            reserved_iv: parse::decode_hex_field::<8>(&input[96..112], 96, "reserved IV")?,
            payload: parse::decode_hex(&input[112..], 112)?,
        })
    }
}

impl Render for PwsafeV2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}{}{}{}",
            crate::format::hex(self.random),
            crate::format::hex(self.digest),
            crate::format::hex(self.reserved_salt),
            crate::format::hex(self.reserved_iv),
            crate::format::hex(&self.payload)
        )
    }
}
