//! bfegg hashes, rendered as a 13-character digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// bfegg hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "bfegg", slug = "bfegg", hashcat = [], john = ["bfegg"])]
pub struct Bfegg {
    /// Encoded digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Bfegg {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 13 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "bfegg digests are 13 characters",
            ));
        }
        Ok(Self {
            digest: input.to_owned(),
        })
    }
}

impl Render for Bfegg {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.digest.clone()
    }
}
