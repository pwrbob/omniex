//! Oracle 12c hashes, rendered as `$oracle12c$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Oracle 12c hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Oracle 12c", slug = "oracle12c", hashcat = [], john = ["Oracle12C"])]
pub struct Oracle12c {
    /// Hex-encoded digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Oracle12c {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$oracle12c$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                11,
                "missing Oracle 12c digest",
            ));
        }
        Ok(Self {
            digest: rest.to_owned(),
        })
    }
}

impl Render for Oracle12c {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$oracle12c${}", self.digest)
    }
}
