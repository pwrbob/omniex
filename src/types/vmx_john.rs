//! vmx hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// vmx hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "VMX keySafe", slug = "vmx-keysafe", hashcat = [], john = ["vmx"])]
pub struct VmxJohn {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for VmxJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$vmx$", 0)?;
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

impl Render for VmxJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$vmx${}", self.data)
    }
}
