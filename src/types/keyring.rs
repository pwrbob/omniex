//! Keyring hashes, rendered as a `$keyring$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// GNOME keyring hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Keyring", slug = "keyring", hashcat = [], john = ["keyring"])]
pub struct Keyring {
    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Keyring {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$keyring$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                9,
                "missing Keyring fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Keyring {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$keyring${}", self.fields)
    }
}
