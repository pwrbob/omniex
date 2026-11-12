//! FortiGate256, rendered as `SH2` followed by base64 salt and digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// FortiGate256 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "FortiGate256 (FortiOS256)",
    slug = "fortigate256",
    hashcat = [40054],
    john = ["Fortigate256"],
)]
pub struct Fortigate256 {
    /// 12-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 12],

    /// 32-byte SHA2-256 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Fortigate256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let encoded = parse::strip_prefix(input, "SH2", 0)?;
        let decoded = parse::decode_base64(encoded, 3)?;
        if decoded.len() != 44 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                3,
                "FortiGate256 value must decode to 44 bytes",
            ));
        }
        let mut salt = [0u8; 12];
        let mut digest = [0u8; 32];
        salt.copy_from_slice(&decoded[..12]);
        digest.copy_from_slice(&decoded[12..]);
        Ok(Self { salt, digest })
    }
}

impl Render for Fortigate256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut bytes = Vec::with_capacity(44);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.digest);
        format!("SH2{}", crate::format::base64(bytes))
    }
}
