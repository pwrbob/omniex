//! Dashlane hashes, rendered as a `$dashlane$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Dashlane hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Dashlane", slug = "dashlane", hashcat = [], john = ["dashlane"])]
pub struct Dashlane {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Dashlane {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$dashlane$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                10,
                "missing Dashlane fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Dashlane {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$dashlane${}", self.fields)
    }
}
