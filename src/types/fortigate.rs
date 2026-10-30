//! FortiGate, rendered as `AK1` followed by base64 salt and digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// FortiGate (FortiOS) hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "FortiGate (FortiOS)",
    slug = "fortigate",
    hashcat = [7000],
    john = ["Fortigate"],
)]
pub struct Fortigate {
    /// The 12-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 12],

    /// The 20-byte SHA1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for Fortigate {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let encoded = parse::strip_prefix(input, "AK1", 0)?;
        let decoded = parse::decode_base64(encoded, 3)?;
        if decoded.len() != 32 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                3,
                "FortiGate value must decode to 32 bytes",
            ));
        }
        let mut salt = [0u8; 12];
        let mut digest = [0u8; 20];
        salt.copy_from_slice(&decoded[..12]);
        digest.copy_from_slice(&decoded[12..]);
        Ok(Self { salt, digest })
    }
}

impl Render for Fortigate {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.digest);
        format!("AK1{}", crate::format::base64(bytes))
    }
}
