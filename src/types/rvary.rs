//! RVARY hashes, rendered as `$rvary$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// RVARY hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "RVARY", slug = "rvary", hashcat = [], john = ["RVARY"])]
pub struct Rvary {
    /// Eight-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for Rvary {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$rvary$", 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<8>(rest, 7, "digest")?,
        })
    }
}

impl Render for Rvary {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$rvary${}", crate::format::hex(self.digest).to_uppercase())
    }
}
