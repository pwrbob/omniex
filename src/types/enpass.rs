//! Enpass hashes, rendered as a `$enpass$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Enpass hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Enpass", slug = "enpass", hashcat = [], john = ["enpass"])]
pub struct Enpass {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Enpass {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$enpass$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                8,
                "missing Enpass fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Enpass {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$enpass${}", self.fields)
    }
}
