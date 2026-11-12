//! PST hashes, rendered as `$pst$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// PST hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PST", slug = "pst", hashcat = [], john = ["PST"])]
pub struct Pst {
    /// 4-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 4],
}

impl Parse for Pst {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pst$", 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<4>(rest, 5, "digest")?,
        })
    }
}

impl Render for Pst {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$pst${}", crate::format::hex(self.digest))
    }
}
