//! PBKDF2-HMAC-SHA512 over UTF-16LE passwords, rendered as
//! `sha512utf16le:<iterations>:<salt>:<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PBKDF2-HMAC-SHA512 over UTF-16LE passwords.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PBKDF2-HMAC-SHA512 (UTF-16LE)",
    slug = "pbkdf2-sha512-utf16",
    hashcat = [36600]
)]
pub struct Pbkdf2Sha512Utf16 {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Base64 salt.
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// Base64 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for Pbkdf2Sha512Utf16 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "sha512utf16le:", 0)?;
        let fields = parse::split_fields(rest, ':', 3)?;
        let iterations = fields[0].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid PBKDF2 iteration count",
            )
        })?;
        Ok(Self {
            iterations,
            salt: parse::decode_base64(fields[1].0, fields[1].1)?,
            digest: parse::decode_base64(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for Pbkdf2Sha512Utf16 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "sha512utf16le:{}:{}:{}",
            self.iterations,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.digest)
        )
    }
}
