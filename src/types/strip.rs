//! STRIP hashes, rendered as `$strip$*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// STRIP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "STRIP", slug = "strip", hashcat = [], john = ["STRIP"])]
pub struct Strip {
    /// Hex-encoded digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Strip {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$strip$*", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                8,
                "missing STRIP digest",
            ));
        }
        Ok(Self {
            digest: rest.to_owned(),
        })
    }
}

impl Render for Strip {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$strip$*{}", self.digest)
    }
}
