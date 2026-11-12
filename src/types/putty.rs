//! PuTTY hashes, rendered as a `$putty$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PuTTY private key hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PuTTY", slug = "putty", hashcat = [], john = ["PuTTY"])]
pub struct Putty {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Putty {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$putty$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                7,
                "missing PuTTY fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Putty {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$putty${}", self.fields)
    }
}
