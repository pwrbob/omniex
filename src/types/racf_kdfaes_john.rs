//! RACF-KDFAES hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// RACF-KDFAES hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "RACF-KDFAES", slug = "racf-kdfaes-john", hashcat = [], john = ["RACF-KDFAES"])]
pub struct RacfKdfaesJohn {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for RacfKdfaesJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$racf$", 0)?;
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

impl Render for RacfKdfaesJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$racf${}", self.data)
    }
}
