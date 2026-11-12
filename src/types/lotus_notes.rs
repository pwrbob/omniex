//! Lotus Notes/Domino 6 and 8, rendered as a parenthesized encoded value.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Lotus Notes/Domino 6 and 8 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Lotus Notes/Domino 6/8",
    slug = "lotus-notes",
    hashcat = [8700, 9100],
)]
pub struct LotusNotes {
    /// Parenthesized digest
    #[field(role = digest, encoding = ascii)]
    pub value: String,
}

impl Parse for LotusNotes {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if !input.starts_with('(') || !input.ends_with(')') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "Lotus Notes values are parenthesized",
            ));
        }
        Ok(Self {
            value: input.to_owned(),
        })
    }
}

impl Render for LotusNotes {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.value.clone()
    }
}
