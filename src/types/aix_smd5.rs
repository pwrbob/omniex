//! AIX {smd5}, rendered as `{smd5}<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AIX MD5 modular crypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "AIX {smd5}",
    slug = "aix-smd5",
    hashcat = [6300],
)]
pub struct AixSmd5 {
    /// Up to eight salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Twenty-two digest characters.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for AixSmd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "{smd5}", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 6)?;

        if salt.len() > 8 || !salt.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                6,
                "AIX smd5 salt must be at most eight crypt characters",
            ));
        }
        if digest.len() != 22 || !digest.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6 + digest_offset,
                "AIX smd5 digest must be 22 crypt characters",
            ));
        }

        Ok(Self {
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for AixSmd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{{smd5}}{}${}", self.salt, self.digest)
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
