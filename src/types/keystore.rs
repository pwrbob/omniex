//! Android keystore hashes, rendered as a `$keystore$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Android keystore hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Keystore", slug = "keystore", hashcat = [], john = ["keystore"])]
pub struct Keystore {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Keystore {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$keystore$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                10,
                "missing keystore fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Keystore {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$keystore${}", self.fields)
    }
}
