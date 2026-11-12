//! PGP WDE hashes, rendered as a `$pgpwde$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PGP Whole Disk Encryption hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PGP WDE", slug = "pgpwde", hashcat = [], john = ["pgpwde"])]
pub struct Pgpwde {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Pgpwde {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pgpwde$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                8,
                "missing PGP WDE fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Pgpwde {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$pgpwde${}", self.fields)
    }
}
