//! Cisco-ASA MD5, rendered as `<crypt>:<salt>`.

use crate::parse;
use crate::{
    HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions, Tool,
};

/// Cisco-ASA MD5 password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Cisco-ASA MD5",
    slug = "cisco-asa",
    hashcat = [2410],
    john = ["asa-md5"],
)]
pub struct CiscoAsa {
    /// 16-character crypt string
    #[field(role = digest, encoding = ascii)]
    pub crypt: String,

    /// Decimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for CiscoAsa {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let (first, second, second_offset) = parse::split_once(input, ':', 0)?;
        let first_offset = 0;
        let is_crypt = |value: &str| value.len() == 16 && value.bytes().all(is_crypt_character);
        let is_salt = |value: &str| {
            !value.is_empty() && value.len() <= 4 && value.bytes().all(|byte| byte.is_ascii_digit())
        };
        let (crypt, salt, crypt_offset, salt_offset) = if is_crypt(first) && is_salt(second) {
            (first, second, first_offset, second_offset)
        } else if is_crypt(second) && is_salt(first) {
            (second, first, second_offset, first_offset)
        } else if !is_crypt(first) && !is_crypt(second) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                first_offset,
                "Cisco-ASA crypt string must be 16 characters",
            ));
        } else {
            let salt_offset = if is_crypt(second) {
                first_offset
            } else {
                second_offset
            };
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "Cisco-ASA salt must be 1 to 4 decimal digits",
            ));
        };
        if crypt.len() != 16 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                crypt_offset,
                "Cisco-ASA crypt string must be 16 characters",
            ));
        }
        if !crypt.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                crypt_offset,
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
    fn render_value(&self, opts: &RenderOptions) -> String {
        if opts.tool == Tool::John {
            return format!("{}:{}", self.salt, self.crypt);
        }
        format!("{}:{}", self.crypt, self.salt)
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
