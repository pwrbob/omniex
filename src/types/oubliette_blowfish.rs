//! John Oubliette-Blowfish hashes, rendered as `$oubliette-blowfish$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Oubliette password hash using Blowfish.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Oubliette-Blowfish",
    slug = "oubliette-blowfish",
    john = ["Oubliette-Blowfish"],
)]
pub struct OublietteBlowfish {
    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for OublietteBlowfish {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$oubliette-blowfish$", 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<32>(rest, 20, "digest")?,
        })
    }
}

impl Render for OublietteBlowfish {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$oubliette-blowfish${}", crate::format::hex(self.digest))
    }
}
