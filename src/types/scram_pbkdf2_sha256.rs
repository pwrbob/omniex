//! SCRAM-PBKDF2-SHA256 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SCRAM-PBKDF2-SHA256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "SCRAM-PBKDF2-SHA256", slug = "scram-pbkdf2-sha256", hashcat = [], john = ["SCRAM-PBKDF2-SHA256"])]
pub struct ScramPbkdf2Sha256John {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for ScramPbkdf2Sha256John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$scram-pbkdf2-sha256$", 0)?;
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

impl Render for ScramPbkdf2Sha256John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$scram-pbkdf2-sha256${}", self.data)
    }
}
