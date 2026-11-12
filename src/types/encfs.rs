//! EncFS hashes, rendered as a `$encfs$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// EncFS hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "EncFS", slug = "encfs", hashcat = [], john = ["EncFS"])]
pub struct Encfs {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Encfs {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$encfs$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                7,
                "missing EncFS fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Encfs {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$encfs${}", self.fields)
    }
}
