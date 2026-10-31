//! Sybase-PROP hashes, rendered as `0x<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Sybase-PROP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Sybase-PROP", slug = "sybase-prop", hashcat = [], john = ["Sybase-PROP"])]
pub struct SybaseProp {
    /// Hexadecimal digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for SybaseProp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "0x", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                2,
                "missing Sybase-PROP digest",
            ));
        }
        Ok(Self {
            digest: rest.to_owned(),
        })
    }
}

impl Render for SybaseProp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("0x{}", self.digest)
    }
}
