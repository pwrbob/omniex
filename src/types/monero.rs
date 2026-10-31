//! Monero wallet hashes, rendered as `$monero$<fields>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Monero wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Monero", slug = "monero", hashcat = [], john = ["Monero"])]
pub struct Monero {
    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Monero {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$monero$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                8,
                "missing Monero fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Monero {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$monero${}", self.fields)
    }
}
