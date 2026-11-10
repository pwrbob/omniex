//! SCRAM-PBKDF2-SHA1-MongoDB hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SCRAM-PBKDF2-SHA1-MongoDB hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "SCRAM-PBKDF2-SHA1-MongoDB legacy", slug = "scram-pbkdf2-sha1-mongodb", hashcat = [], john = ["SCRAM-PBKDF2-SHA1-MongoDB"])]
pub struct ScramJohn {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for ScramJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$scram$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "missing hash payload",
            ));
        }
        Ok(Self {
            data: rest.to_owned(),
        })
    }
}

impl Render for ScramJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$scram${}", self.data)
    }
}
