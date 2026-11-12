//! gost-yescrypt hashes, rendered as a complete `$gy$` crypt string.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// gost-yescrypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "gost-yescrypt", slug = "gost-yescrypt", hashcat = [36200])]
pub struct GostYescrypt {
    /// Complete crypt string
    #[field(role = salt, encoding = ascii)]
    pub crypt: String,
}

impl Parse for GostYescrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$gy$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                4,
                "missing gost-yescrypt settings",
            ));
        }
        Ok(Self {
            crypt: input.to_owned(),
        })
    }
}

impl Render for GostYescrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.crypt.clone()
    }
}
