//! yescrypt hashes, rendered as a complete `$y$` crypt string.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// yescrypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "yescrypt", slug = "yescrypt", hashcat = [36100])]
pub struct Yescrypt {
    /// Complete crypt string.
    #[field(role = salt, encoding = ascii)]
    pub crypt: String,
}

impl Parse for Yescrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$y$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                3,
                "missing yescrypt settings",
            ));
        }
        Ok(Self {
            crypt: input.to_owned(),
        })
    }
}

impl Render for Yescrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.crypt.clone()
    }
}
