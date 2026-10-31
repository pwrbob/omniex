//! Anope IRC Services SHA256 hashes, rendered as
//! `sha256:<salt>:<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Anope IRC Services SHA256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Anope IRC Services", slug = "anope-sha256", hashcat = [30700])]
pub struct AnopeSha256 {
    /// Salt value.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],

    /// Thirty-two-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for AnopeSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "sha256:", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, ':', 7)?;
        Ok(Self {
            salt: parse::decode_hex_field::<32>(salt, 7, "salt")?,
            digest: parse::decode_hex_field::<32>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for AnopeSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "sha256:{}:{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
