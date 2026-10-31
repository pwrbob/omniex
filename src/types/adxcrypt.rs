//! adxcrypt hashes, rendered as `$adxcrypt$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// adxcrypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "adxcrypt", slug = "adxcrypt", hashcat = [], john = ["adxcrypt"])]
pub struct Adxcrypt {
    /// Encoded payload.
    #[field(role = salt, encoding = ascii)]
    pub payload: String,
}

impl Parse for Adxcrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$adxcrypt$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                11,
                "missing adxcrypt payload",
            ));
        }
        Ok(Self {
            payload: rest.to_owned(),
        })
    }
}

impl Render for Adxcrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$adxcrypt${}", self.payload)
    }
}
