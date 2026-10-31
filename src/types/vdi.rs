//! VDI hashes, rendered as a `$vdi$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// VirtualBox VDI hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "VDI", slug = "vdi", hashcat = [], john = ["vdi"])]
pub struct Vdi {
    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Vdi {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$vdi$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                5,
                "missing VDI fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Vdi {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$vdi${}", self.fields)
    }
}
