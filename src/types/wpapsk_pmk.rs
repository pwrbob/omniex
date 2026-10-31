//! wpapsk-pmk hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// wpapsk-pmk hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "wpapsk-pmk", slug = "wpapsk-pmk", hashcat = [], john = ["wpapsk-pmk"])]
pub struct WpapskPmkJohn {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for WpapskPmkJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$WPAPSK$", 0)?;
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

impl Render for WpapskPmkJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$WPAPSK${}", self.data)
    }
}
