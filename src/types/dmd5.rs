//! DIGEST-MD5 hashes, rendered as a `$DIGEST-MD5$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SASL DIGEST-MD5 hashes in the John serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "DIGEST-MD5 (John)", slug = "dmd5", hashcat = [], john = ["dmd5"])]
pub struct Dmd5 {
    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Dmd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$DIGEST-MD5$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                12,
                "missing DIGEST-MD5 fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Dmd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$DIGEST-MD5${}", self.fields)
    }
}
