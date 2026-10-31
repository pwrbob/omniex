//! PKZIP Master Key, rendered as a hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// PKZIP master keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "PKZIP Master Key",
    slug = "pkzip-master-key",
    hashcat = [20500, 20510],
)]
pub struct PkzipMasterKey {
    /// The 12-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 12],
}

impl Parse for PkzipMasterKey {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<12>(input, 0, "digest")?,
        })
    }
}

impl Render for PkzipMasterKey {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
