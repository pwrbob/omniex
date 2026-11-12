//! Tripcode, rendered as its ten-character key.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Tripcode keys.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Tripcode",
    slug = "tripcode",
    hashcat = [16000], john = ["tripcode"],
)]
pub struct Tripcode {
    /// 10-character tripcode key
    #[field(role = digest, encoding = ascii)]
    pub key: String,
}

impl Parse for Tripcode {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 10 || !input.bytes().all(is_tripcode_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "tripcode keys are ten crypt64 characters",
            ));
        }
        Ok(Self {
            key: input.to_owned(),
        })
    }
}

impl Render for Tripcode {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.key.clone()
    }
}

fn is_tripcode_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
