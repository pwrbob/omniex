//! EIGRP hashes, rendered as a `$eigrp$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// EIGRP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "EIGRP", slug = "eigrp", hashcat = [], john = ["eigrp"])]
pub struct Eigrp {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Eigrp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$eigrp$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                7,
                "missing EIGRP fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Eigrp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$eigrp${}", self.fields)
    }
}
