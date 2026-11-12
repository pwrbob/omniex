//! SL3 hashes, rendered as `$sl3$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// SL3 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "SL3", slug = "sl3", hashcat = [], john = ["SL3"])]
pub struct Sl3 {
    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 20-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for Sl3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sl3$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 5)?;
        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<20>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Sl3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$sl3${}${}", self.salt, crate::format::hex(self.digest))
    }
}
