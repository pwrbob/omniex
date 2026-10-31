//! HSRP hashes, rendered as `$hsrp$<data>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// HSRP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "HSRP", slug = "hsrp", hashcat = [], john = ["hsrp"])]
pub struct Hsrp {
    /// Packet data.
    #[field(role = salt, encoding = ascii)]
    pub data: String,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Hsrp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$hsrp$", 0)?;
        let (data, digest, digest_offset) = parse::split_once(rest, '$', 6)?;
        Ok(Self {
            data: data.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Hsrp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$hsrp${}${}", self.data, crate::format::hex(self.digest))
    }
}
