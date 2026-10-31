//! Keplr hashes, rendered as a `$keplr$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Keplr wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Keplr", slug = "keplr", hashcat = [], john = ["keplr"])]
pub struct Keplr {
    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Keplr {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$keplr$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                7,
                "missing Keplr fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Keplr {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$keplr${}", self.fields)
    }
}
