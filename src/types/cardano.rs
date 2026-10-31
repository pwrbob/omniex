//! Cardano Eternl wallet hashes, rendered as `ETERNL:<payload>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Cardano Eternl wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Cardano Eternl Wallet", slug = "cardano", hashcat = [37700])]
pub struct Cardano {
    /// Encoded payload.
    #[field(role = salt, encoding = ascii)]
    pub payload: String,
}

impl Parse for Cardano {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "ETERNL:", 0)?;
        if rest.len() < 16 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                7,
                "Cardano payloads are at least 16 characters",
            ));
        }
        Ok(Self {
            payload: rest.to_owned(),
        })
    }
}

impl Render for Cardano {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("ETERNL:{}", self.payload)
    }
}
