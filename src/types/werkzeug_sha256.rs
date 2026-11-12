//! Python Werkzeug SHA256 hashes, rendered as `sha256$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Python Werkzeug SHA256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Python Werkzeug SHA256",
    slug = "werkzeug-sha256",
    hashcat = [30120]
)]
pub struct WerkzeugSha256 {
    /// Salt value
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for WerkzeugSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "sha256$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 7)?;
        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<32>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for WerkzeugSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("sha256${}${}", self.salt, crate::format::hex(self.digest))
    }
}
