//! OpenVMS hashes, rendered as `$V$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// OpenVMS hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "OpenVMS", slug = "openvms", hashcat = [], john = ["OpenVMS"])]
pub struct Openvms {
    /// Encoded payload
    #[field(role = salt, encoding = ascii)]
    pub payload: String,
}

impl Parse for Openvms {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$V$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                3,
                "missing OpenVMS payload",
            ));
        }
        Ok(Self {
            payload: rest.to_owned(),
        })
    }
}

impl Render for Openvms {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$V${}", self.payload)
    }
}
