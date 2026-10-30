//! BSDi extended DES crypt, rendered as its twenty-character setting.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// BSDi extended DES crypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "BSDi Crypt, Extended DES",
    slug = "bsdi-crypt",
    hashcat = [12400],
)]
pub struct BsdiCrypt {
    /// Twenty crypt characters.
    #[field(role = digest, encoding = ascii)]
    pub crypt: String,
}

impl Parse for BsdiCrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 20
            || !input.starts_with('_')
            || !input[1..].bytes().all(is_crypt_character)
        {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "BSDi crypt values are 20 crypt characters starting with `_`",
            ));
        }
        Ok(Self {
            crypt: input.to_owned(),
        })
    }
}

impl Render for BsdiCrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.crypt.clone()
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
