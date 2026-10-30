//! Traditional DES crypt, rendered as the 13-character crypt string.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// descrypt password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "descrypt",
    slug = "descrypt",
    hashcat = [1500],
    john = ["descrypt", "crypt"],
)]
pub struct DesCrypt {
    /// The 13-character crypt string.
    #[field(role = digest, encoding = ascii)]
    pub crypt: String,
}

impl Parse for DesCrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 13 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "descrypt hash must be 13 characters",
            ));
        }
        if !input.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "descrypt hash must use the crypt alphabet",
            ));
        }

        Ok(Self {
            crypt: input.to_owned(),
        })
    }
}

impl Render for DesCrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.crypt.clone()
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
