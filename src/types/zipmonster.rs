//! ZipMonster hashes, rendered as `$zipmonster$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// ZipMonster hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "ZipMonster", slug = "zipmonster", hashcat = [], john = ["ZipMonster"])]
pub struct Zipmonster {
    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Zipmonster {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$zipmonster$", 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<16>(rest, 12, "digest")?,
        })
    }
}

impl Render for Zipmonster {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$zipmonster${}", crate::format::hex(self.digest))
    }
}
