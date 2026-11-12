//! QNX 7 shadow SHA2-512, rendered as `@S@<digest>@<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// QNX 7 shadow SHA2-512 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "QNX 7 /etc/shadow (SHA512)",
    slug = "qnx7-sha512",
    hashcat = [40041],
)]
pub struct Qnx7Sha512 {
    /// 64-byte digest
    #[field(role = digest, encoding = base64)]
    pub digest: [u8; 64],

    /// Salt
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,
}

impl Parse for Qnx7Sha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "@S@", 0)?;
        let (digest, salt, salt_offset) = parse::split_once(rest, '@', 3)?;
        let digest_bytes = parse::decode_base64(digest, 3)?;
        let digest = digest_bytes.as_slice().try_into().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidLength,
                3,
                "QNX 7 digest must be 64 bytes",
            )
        })?;
        Ok(Self {
            digest,
            salt: parse::decode_base64(salt, 3 + salt_offset)?,
        })
    }
}

impl Render for Qnx7Sha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "@S@{}@{}",
            crate::format::base64(self.digest),
            crate::format::base64(&self.salt)
        )
    }
}
