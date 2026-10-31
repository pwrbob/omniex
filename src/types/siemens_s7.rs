//! Siemens-S7 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Siemens-S7 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Siemens-S7", slug = "siemens-s7", hashcat = [], john = ["Siemens-S7"])]
pub struct SiemensS7John {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for SiemensS7John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$siemens-s7$", 0)?;
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

impl Render for SiemensS7John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$siemens-s7${}", self.data)
    }
}
