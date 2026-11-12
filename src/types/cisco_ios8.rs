//! Cisco-IOS `$8$`, rendered as `$8$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Cisco-IOS PBKDF2-SHA256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Cisco-IOS $8$ (PBKDF2-SHA256)",
    slug = "cisco-ios8",
    hashcat = [40021],
)]
pub struct CiscoIos8 {
    /// 14-character salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 43-character digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for CiscoIos8 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$8$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 3)?;
        if salt.len() != 14 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                3,
                "Cisco-IOS $8$ salt must be 14 characters",
            ));
        }
        if digest.len() != 43 || !digest.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                3 + digest_offset,
                "Cisco-IOS $8$ digest must be 43 crypt characters",
            ));
        }

        Ok(Self {
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for CiscoIos8 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$8${}${}", self.salt, self.digest)
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
