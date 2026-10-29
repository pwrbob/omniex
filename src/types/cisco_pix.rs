//! Cisco-PIX MD5, rendered as the 16-character crypt string.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Cisco-PIX MD5 password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Cisco-PIX MD5",
    slug = "cisco-pix",
    hashcat = [2400],
    john = ["pix-md5"],
)]
pub struct CiscoPix {
    /// The 16-character crypt string.
    #[field(role = digest, encoding = ascii)]
    pub crypt: String,
}

impl Parse for CiscoPix {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 16 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Cisco-PIX hash must be 16 characters",
            ));
        }
        if !input.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "Cisco-PIX hash must use the crypt alphabet",
            ));
        }

        Ok(Self {
            crypt: input.to_owned(),
        })
    }
}

impl Render for CiscoPix {
    fn render(&self, _opts: &RenderOptions) -> String {
        self.crypt.clone()
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
