//! John Oubliette-IDEA hashes, rendered as `$oubliette-idea$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Oubliette password hash using IDEA.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Oubliette-IDEA",
    slug = "oubliette-idea",
    john = ["Oubliette-IDEA"],
)]
pub struct OublietteIdea {
    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for OublietteIdea {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$oubliette-idea$", 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<32>(rest, 15, "digest")?,
        })
    }
}

impl Render for OublietteIdea {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$oubliette-idea${}", crate::format::hex(self.digest))
    }
}
