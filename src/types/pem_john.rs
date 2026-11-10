//! PEM hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PEM hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "PKCS#8 PBES2", slug = "pkcs8-pbes2", hashcat = [], john = ["PEM"])]
pub struct PemJohn {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for PemJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$PEM$", 0)?;
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

impl Render for PemJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$PEM${}", self.data)
    }
}
