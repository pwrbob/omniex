//! John IKE hashes, rendered as `$ike$<fields>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// IKE hashes in the John serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "IKE payload", slug = "ike-payload", hashcat = [], john = ["IKE"])]
pub struct IkeJohn {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for IkeJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$ike$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                5,
                "missing IKE fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for IkeJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$ike${}", self.fields)
    }
}
