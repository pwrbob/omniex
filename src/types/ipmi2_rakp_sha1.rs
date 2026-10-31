//! IPMI2 RAKP HMAC-SHA1 hashes, rendered as `<salt>:<digest>` in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// IPMI2 RAKP HMAC-SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "IPMI2 RAKP HMAC-SHA1", slug = "ipmi2-rakp-sha1", hashcat = [7300])]
pub struct Ipmi2RakpSha1 {
    /// Random session salt bytes.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// HMAC-SHA1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for Ipmi2RakpSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (salt, digest, digest_offset) = parse::split_once(input, ':', 0)?;
        if salt.len() < 64 || salt.len() > 512 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "IPMI2 RAKP salts are between 32 and 256 bytes",
            ));
        }
        Ok(Self {
            salt: parse::decode_hex(salt, 0)?,
            digest: parse::decode_hex_field::<20>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Ipmi2RakpSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(&self.salt),
            crate::format::hex(self.digest)
        )
    }
}
