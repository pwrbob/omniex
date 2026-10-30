//! NetNTLMv1, rendered as its complete challenge-response string.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetNTLMv1 challenge-response.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetNTLMv1",
    slug = "netntlmv1",
    hashcat = [5500],
)]
pub struct NetNtlmV1 {
    /// Complete NetNTLMv1 string.
    #[field(role = ciphertext, encoding = ascii)]
    pub blob: String,
}

impl Parse for NetNtlmV1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if !input.contains("::") {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected a NetNTLM `user::domain` separator",
            ));
        }
        Ok(Self {
            blob: input.to_owned(),
        })
    }
}

impl Render for NetNtlmV1 {
    fn render(&self, _opts: &RenderOptions) -> String {
        self.blob.clone()
    }
}
