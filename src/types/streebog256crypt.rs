//! streebog256crypt hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// streebog256crypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "streebog256crypt", slug = "streebog256crypt", hashcat = [], john = ["streebog256crypt"])]
pub struct Streebog256cryptJohn {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Streebog256cryptJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$gost12256hash$", 0)?;
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

impl Render for Streebog256cryptJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$gost12256hash${}", self.data)
    }
}
