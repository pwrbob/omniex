//! Oracle 11g SHA-1, rendered as `<digest>:<salt>` with a hex salt.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Oracle 11g password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Oracle 11g SHA1",
    slug = "oracle-sha1",
    hashcat = [112],
)]
pub struct OracleSha1 {
    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// The 10-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 10],
}

impl Parse for OracleSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;

        Ok(Self {
            digest: parse::decode_hex_field::<20>(digest, 0, "digest")?,
            salt: parse::decode_hex_field::<10>(salt, salt_offset, "salt")?,
        })
    }
}

impl Render for OracleSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(self.salt)
        )
    }
}
