//! Cisco-ASA MD5, rendered as `<crypt>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Cisco-ASA MD5 password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Cisco-ASA MD5",
    slug = "cisco-asa",
    hashcat = [2410],
)]
pub struct CiscoAsa {
    /// The 16-character crypt string.
    #[field(role = digest, encoding = ascii)]
    pub crypt: String,

    /// Decimal salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for CiscoAsa {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let (crypt, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        if crypt.len() != 16 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Cisco-ASA crypt string must be 16 characters",
            ));
        }
        if !crypt.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "Cisco-ASA crypt string must use the crypt alphabet",
            ));
        }
        if salt.is_empty() || salt.len() > 4 || !salt.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "Cisco-ASA salt must be 1 to 4 decimal digits",
            ));
        }

        Ok(Self {
            crypt: crypt.to_owned(),
            salt: salt.to_owned(),
        })
    }
}

impl Render for CiscoAsa {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", self.crypt, self.salt)
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
