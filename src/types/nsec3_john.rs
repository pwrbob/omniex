//! nsec3 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// nsec3 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "nsec3", slug = "nsec3-john", hashcat = [], john = ["nsec3"])]
pub struct Nsec3John {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Nsec3John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$NSEC3$", 0)?;
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

impl Render for Nsec3John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$NSEC3${}", self.data)
    }
}
