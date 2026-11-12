//! John Cardano hashes, rendered as `$cardano$<fields>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Cardano hashes in the John serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Cardano payload",
    slug = "cardano-payload",
    hashcat = [],
    john = ["cardano"]
)]
pub struct CardanoJohn {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for CardanoJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$cardano$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                9,
                "missing Cardano fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for CardanoJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$cardano${}", self.fields)
    }
}
