//! IPB2 hashes, rendered as `$IPB2$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// IPB2 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "IPB2", slug = "ipb2", hashcat = [], john = ["ipb2"])]
pub struct Ipb2 {
    /// Five-byte salt as hexadecimal.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Ipb2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$IPB2$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 6)?;
        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Ipb2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$IPB2${}${}", self.salt, crate::format::hex(self.digest))
    }
}
