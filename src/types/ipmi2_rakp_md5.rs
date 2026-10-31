//! IPMI2 RAKP HMAC-MD5 hashes, rendered as `<digest>:<salt>` in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// IPMI2 RAKP HMAC-MD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "IPMI2 RAKP HMAC-MD5", slug = "ipmi2-rakp-md5", hashcat = [7350])]
pub struct Ipmi2RakpMd5 {
    /// HMAC-MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Random session salt bytes.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,
}

impl Parse for Ipmi2RakpMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<16>(digest, 0, "digest")?,
            salt: parse::decode_hex(salt, salt_offset)?,
        })
    }
}

impl Render for Ipmi2RakpMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(&self.salt)
        )
    }
}
