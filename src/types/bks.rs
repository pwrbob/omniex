//! BKS hashes, rendered as a `$bks$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// BKS keystore hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "BKS", slug = "bks", hashcat = [], john = ["BKS"])]
pub struct Bks {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Bks {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$bks$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                5,
                "missing BKS fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Bks {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$bks${}", self.fields)
    }
}
